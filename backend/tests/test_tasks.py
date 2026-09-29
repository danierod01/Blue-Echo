"""Tests de la cola de tareas en segundo plano (roadmap R3, Celery+Redis).

No requieren un Redis real: el núcleo de la tarea se prueba directamente con
enrich/IA mockeados y una BD en memoria, y los endpoints se prueban aislando
Celery (delay/AsyncResult mockeados).
"""

import asyncio
import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from ioc_correlator.connectors.base import ConnectorResult  # noqa: E402
from ioc_correlator.database import ScanResult  # noqa: E402
import ioc_correlator.tasks as tasks  # noqa: E402

_VT = ConnectorResult(
    source="virustotal", success=True,
    data={"malicious": 23, "suspicious": 0, "total": 87, "stats": {}},
    verdict="malicious", summary="VT",
)


@pytest.fixture
def mem_engine(monkeypatch):
    """BD en memoria compartida, inyectada como engine que usa la tarea."""
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(tasks, "engine", engine)

    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT}

    async def fake_summary(*a, **k):
        return "Resumen IA de prueba."

    async def fake_alert(*a, **k):
        return None

    monkeypatch.setattr(tasks, "enrich", fake_enrich)
    monkeypatch.setattr(tasks, "generate_summary", fake_summary)
    monkeypatch.setattr(tasks, "maybe_send_alert", fake_alert)
    return engine


# ---------------------------------------------------------------------------
# Núcleo de la tarea
# ---------------------------------------------------------------------------

def test_async_scan_persists_and_returns_summary(mem_engine):
    result = asyncio.run(tasks._async_scan("1.1.1.1", api_key="tokenA"))
    assert result["ioc_type"] == "ipv4"
    assert result["verdict"] in ("clean", "suspicious", "malicious", "critical")
    assert result["score"] >= 30  # VT malicious aporta +30
    # La fila quedó guardada en la BD del worker
    with Session(mem_engine) as s:
        rows = s.exec(select(ScanResult)).all()
    assert len(rows) == 1
    assert rows[0].ioc_value == "1.1.1.1"
    assert rows[0].api_key == "tokenA"


def test_async_scan_unknown_ioc_returns_error(mem_engine):
    result = asyncio.run(tasks._async_scan("no-es-un-ioc-valido!!", api_key=None))
    assert "error" in result


def test_celery_task_wrapper_runs(mem_engine):
    # La tarea Celery envuelve _async_scan con asyncio.run.
    result = tasks.scan_ioc_task.run("8.8.8.8", None)
    assert result["ioc_value"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# Endpoints (Celery aislado)
# ---------------------------------------------------------------------------

from main import app  # noqa: E402
import ioc_correlator.api.routes as routes  # noqa: E402


@pytest.fixture(name="client")
def _client():
    with TestClient(app) as c:
        yield c


def test_scan_async_enqueues(client, monkeypatch):
    class FakeTask:
        id = "abc-123"
    monkeypatch.setattr(routes.scan_ioc_task, "delay", lambda *a, **k: FakeTask())
    r = client.post("/api/scan/async", json={"ioc": "1.1.1.1"})
    assert r.status_code == 200
    body = r.json()
    assert body["task_id"] == "abc-123"
    assert body["status"] == "queued"


def test_task_status_success(client, monkeypatch):
    class FakeResult:
        status = "SUCCESS"
        result = {"id": 5, "verdict": "critical", "score": 87}
        def __init__(self, *a, **k): pass
        def successful(self): return True
        def failed(self): return False
    monkeypatch.setattr(routes, "AsyncResult", FakeResult)
    r = client.get("/api/tasks/abc-123")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "SUCCESS"
    assert body["result"]["verdict"] == "critical"


def test_task_status_failure(client, monkeypatch):
    class FakeResult:
        status = "FAILURE"
        result = RuntimeError("boom")
        def __init__(self, *a, **k): pass
        def successful(self): return False
        def failed(self): return True
    monkeypatch.setattr(routes, "AsyncResult", FakeResult)
    r = client.get("/api/tasks/xyz")
    assert r.status_code == 200
    assert "boom" in r.json()["error"]
