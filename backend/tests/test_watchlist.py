"""Tests de la watchlist / monitorización continua (SOC-B) y del dashboard de
estadísticas (SOC-D)."""

import asyncio
import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from ioc_correlator import database as db  # noqa: E402
from ioc_correlator.database import (  # noqa: E402
    get_session, save_scan,
    add_watched_ioc, list_watched_iocs, remove_watched_ioc, record_watch_check,
    iocs_due_for_check, list_watch_alerts, ack_watch_alert, get_stats, WatchedIoc,
)
from ioc_correlator.connectors.base import ConnectorResult  # noqa: E402


@pytest.fixture(name="session")
def _session():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Helpers de BD
# ---------------------------------------------------------------------------

def test_add_watched_is_idempotent(session):
    a = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tok")
    b = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tok")
    assert a.id == b.id
    assert len(list_watched_iocs(session, api_key="tok")) == 1


def test_watchlist_isolated_per_token(session):
    add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tokA")
    add_watched_ioc(session, ioc_value="2.2.2.2", ioc_type="ipv4", api_key="tokB")
    assert {w.ioc_value for w in list_watched_iocs(session, api_key="tokA")} == {"1.1.1.1"}
    assert {w.ioc_value for w in list_watched_iocs(session, api_key="tokB")} == {"2.2.2.2"}


def test_remove_respects_owner(session):
    w = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tokA")
    assert remove_watched_ioc(session, w.id, api_key="tokB") is False   # ajeno
    assert remove_watched_ioc(session, w.id, api_key="tokA") is True
    assert list_watched_iocs(session, api_key="tokA") == []


def test_verdict_change_creates_alert(session):
    w = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tok")
    # Primer chequeo: no hay veredicto previo → sin alerta.
    assert record_watch_check(session, w, score=5, verdict="clean") is None
    # Mismo veredicto → sin alerta.
    assert record_watch_check(session, w, score=8, verdict="clean") is None
    # Cambio de veredicto → alerta.
    alert = record_watch_check(session, w, score=85, verdict="critical")
    assert alert is not None
    assert alert.old_verdict == "clean" and alert.new_verdict == "critical"
    alerts = list_watch_alerts(session, api_key="tok")
    assert len(alerts) == 1 and alerts[0].acknowledged is False


def test_ack_alert(session):
    w = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tok")
    record_watch_check(session, w, score=5, verdict="clean")
    alert = record_watch_check(session, w, score=85, verdict="critical")
    assert ack_watch_alert(session, alert.id, api_key="otro") is False
    assert ack_watch_alert(session, alert.id, api_key="tok") is True
    assert list_watch_alerts(session, api_key="tok")[0].acknowledged is True


def test_iocs_due_for_check(session):
    w = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tok")
    # Nunca comprobado → vencido.
    assert w in iocs_due_for_check(session, older_than_minutes=60)
    # Tras registrar un chequeo ahora, ya no está vencido para 60 min.
    record_watch_check(session, w, score=5, verdict="clean")
    assert iocs_due_for_check(session, older_than_minutes=60) == []


# ---------------------------------------------------------------------------
# Estadísticas (SOC-D)
# ---------------------------------------------------------------------------

def test_get_stats_aggregates(session):
    for ioc, verdict, score in [
        ("1.1.1.1", "critical", 90), ("2.2.2.2", "malicious", 60),
        ("3.3.3.3", "clean", 0), ("evil.com", "critical", 88),
    ]:
        t = "domain" if ioc.endswith(".com") else "ipv4"
        save_scan(session, ioc_value=ioc, ioc_type=t, score=score, verdict=verdict,
                  connector_results={}, ai_summary="", api_key="tok")
    stats = get_stats(session, api_key="tok")
    assert stats["total_scans"] == 4
    assert stats["verdict_counts"]["critical"] == 2
    assert stats["type_counts"]["ipv4"] == 3
    # Top amenazas: solo malicious/critical, ordenadas por score.
    assert stats["top_threats"][0]["ioc_value"] == "1.1.1.1"
    assert all(t["verdict"] in ("malicious", "critical") for t in stats["top_threats"])
    assert len(stats["timeline"]) == 14   # días por defecto


# ---------------------------------------------------------------------------
# Tarea Celery de monitorización (eager + mock)
# ---------------------------------------------------------------------------

def test_check_watchlist_task_creates_alert(session, monkeypatch):
    import ioc_correlator.tasks as tasks

    # La tarea usa el engine global: lo apuntamos a la BD de prueba.
    monkeypatch.setattr(tasks, "engine", session.get_bind())

    w = add_watched_ioc(session, ioc_value="1.1.1.1", ioc_type="ipv4", api_key="tok")
    record_watch_check(session, w, score=5, verdict="clean")   # estado previo: clean

    # enrich mockeado → veredicto malicious (cambio).
    _VT = ConnectorResult(source="virustotal", success=True,
                          data={"malicious": 30, "suspicious": 0, "total": 90, "stats": {}},
                          verdict="malicious", summary="VT")

    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT}

    async def fake_alert(*a, **k):
        return None

    monkeypatch.setattr(tasks, "enrich", fake_enrich)
    monkeypatch.setattr(tasks, "maybe_send_alert", fake_alert)
    monkeypatch.setenv("WATCHLIST_CHECK_INTERVAL_MINUTES", "0")   # todo vencido

    result = asyncio.run(tasks._run_watchlist_checks())
    assert result["checked"] == 1
    assert result["alerts"] == 1
    assert len(list_watch_alerts(session, api_key="tok")) == 1


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

from main import app  # noqa: E402


@pytest.fixture(name="client")
def _client(session, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {}
    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_watchlist_endpoints_flow(client):
    # Añadir
    r = client.post("/api/watchlist", json={"ioc": "1.1.1.1"})
    assert r.status_code == 200 and r.json()["ioc_type"] == "ipv4"
    wid = r.json()["id"]
    # Listar
    assert len(client.get("/api/watchlist").json()) == 1
    # IOC inválido → 422
    assert client.post("/api/watchlist", json={"ioc": "no-válido!!"}).status_code == 422
    # Check manual (enrich mockeado vacío → clean, primer chequeo sin alerta)
    chk = client.post(f"/api/watchlist/{wid}/check")
    assert chk.status_code == 200 and chk.json()["alert"] is None
    # Eliminar
    assert client.delete(f"/api/watchlist/{wid}").status_code == 200
    assert client.get("/api/watchlist").json() == []


def test_stats_endpoint(client, session):
    save_scan(session, ioc_value="1.1.1.1", ioc_type="ipv4", score=90, verdict="critical",
              connector_results={}, ai_summary="", api_key=None)
    r = client.get("/api/stats")
    assert r.status_code == 200
    assert r.json()["total_scans"] == 1
    assert r.json()["verdict_counts"]["critical"] == 1
