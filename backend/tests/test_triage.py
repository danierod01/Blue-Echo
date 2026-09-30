"""Tests del triaje del analista (A-lite): estado + nota + etiquetas."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from ioc_correlator.database import (  # noqa: E402
    get_session, save_scan, update_scan_triage, parse_tags,
)


@pytest.fixture(name="session")
def _session():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _scan(session, api_key=None):
    return save_scan(session, ioc_value="1.1.1.1", ioc_type="ipv4", score=90,
                     verdict="critical", connector_results={}, ai_summary="", api_key=api_key)


# ---------------------------------------------------------------------------
# Helper de BD
# ---------------------------------------------------------------------------

def test_update_triage_sets_fields(session):
    s = _scan(session, api_key="tok")
    updated = update_scan_triage(session, s.id, api_key="tok",
                                 triage="investigating", note="revisar logs",
                                 tags=["tor", "c2"])
    assert updated.triage == "investigating"
    assert updated.note == "revisar logs"
    assert parse_tags(updated.tags) == ["tor", "c2"]


def test_update_triage_invalid_state_raises(session):
    s = _scan(session, api_key="tok")
    with pytest.raises(ValueError):
        update_scan_triage(session, s.id, api_key="tok", triage="inventado")


def test_update_triage_respects_owner(session):
    s = _scan(session, api_key="tokA")
    assert update_scan_triage(session, s.id, api_key="tokB", triage="resolved") is None
    # El propietario sí puede.
    assert update_scan_triage(session, s.id, api_key="tokA", triage="resolved").triage == "resolved"


def test_tags_normalized(session):
    s = _scan(session, api_key="tok")
    updated = update_scan_triage(session, s.id, api_key="tok",
                                 tags=["a", "a", " b ", "", *[f"t{i}" for i in range(15)]])
    parsed = parse_tags(updated.tags)
    assert "a" in parsed and "b" in parsed
    assert parsed.count("a") == 1        # sin duplicados
    assert len(parsed) <= 10             # tope


def test_parse_tags_defensive():
    assert parse_tags("[]") == []
    assert parse_tags("no-es-json") == []
    assert parse_tags('["x","y"]') == ["x", "y"]


# ---------------------------------------------------------------------------
# Endpoint PATCH /history/{id}/triage
# ---------------------------------------------------------------------------

from main import app  # noqa: E402


@pytest.fixture(name="client")
def _client(session):
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_triage_endpoint_updates_and_reflects(client, session):
    s = _scan(session, api_key=None)
    r = client.patch(f"/api/history/{s.id}/triage",
                     json={"triage": "confirmed", "note": "IOC malicioso", "tags": ["tor"]})
    assert r.status_code == 200
    body = r.json()
    assert body["triage"] == "confirmed"
    assert body["note"] == "IOC malicioso"
    assert body["tags"] == ["tor"]
    # Se refleja en el historial.
    hist = client.get("/api/history").json()
    assert hist["items"][0]["triage"] == "confirmed"
    assert hist["items"][0]["tags"] == ["tor"]


def test_triage_endpoint_invalid_state(client, session):
    s = _scan(session, api_key=None)
    r = client.patch(f"/api/history/{s.id}/triage", json={"triage": "xxx"})
    assert r.status_code == 422


def test_triage_endpoint_not_found(client):
    assert client.patch("/api/history/9999/triage", json={"triage": "resolved"}).status_code == 404
