import json
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.utils.validators import IOCType

# ---------------------------------------------------------------------------
# App con BD en memoria y conectores mockeados
# ---------------------------------------------------------------------------

# Patch ANTES de importar la app para que el engine use la BD en memoria
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from main import app  # noqa: E402
from ioc_correlator.database import get_session  # noqa: E402


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# Resultados mock que devolverán los conectores
_VT_OK = ConnectorResult(
    source="virustotal",
    success=True,
    data={"malicious": 23, "suspicious": 0, "total": 87, "stats": {}},
    verdict="malicious",
    summary="VirusTotal: 23/87 motores lo detectan como malicioso.",
)

_ABUSE_OK = ConnectorResult(
    source="abuseipdb",
    success=True,
    data={"confidence": 95, "total_reports": 142, "country": "DE",
          "isp": "Tor", "last_reported": "2026-04-27", "is_whitelisted": False},
    verdict="malicious",
    summary="AbuseIPDB: score de confianza 95%.",
)


# ---------------------------------------------------------------------------
# Tests de GET /api/health
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Tests de POST /api/scan/json
# ---------------------------------------------------------------------------

def test_scan_json_ipv4(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK, "abuseipdb": _ABUSE_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    r = client.post("/api/scan/json", json={"ioc": "185.220.101.45"})
    assert r.status_code == 200
    body = r.json()
    assert body["ioc_value"] == "185.220.101.45"
    assert body["ioc_type"] == "ipv4"
    assert body["score"] == 70          # VT(+30) + AbuseIPDB(+40)
    assert body["verdict"] == "malicious"
    assert "virustotal" in body["connector_results"]
    assert "abuseipdb" in body["connector_results"]
    assert body["id"] is not None


def test_scan_json_domain(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": ConnectorResult(
            source="virustotal", success=True,
            data={"malicious": 3, "suspicious": 0, "total": 87, "stats": {}},
            verdict="suspicious", summary="VT: 3/87",
        )}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    r = client.post("/api/scan/json", json={"ioc": "evil.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["ioc_type"] == "domain"
    assert body["score"] == 15
    assert body["verdict"] == "clean"   # 15 < 21 → clean


def test_scan_json_hash_sha256(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = client.post("/api/scan/json", json={"ioc": h})
    assert r.status_code == 200
    assert r.json()["ioc_type"] == "sha256"


def test_scan_json_unknown_ioc_returns_422(client):
    r = client.post("/api/scan/json", json={"ioc": "not-an-ioc"})
    assert r.status_code == 422


def test_scan_json_stores_in_history(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    client.post("/api/scan/json", json={"ioc": "1.2.3.4"})
    r = client.get("/api/history")
    assert r.status_code == 200
    history = r.json()
    assert any(h["ioc_value"] == "1.2.3.4" for h in history)


# ---------------------------------------------------------------------------
# Tests de POST /api/scan (multipart form)
# ---------------------------------------------------------------------------

def test_scan_form_ioc(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    r = client.post("/api/scan", data={"ioc": "8.8.8.8"})
    assert r.status_code == 200
    assert r.json()["ioc_value"] == "8.8.8.8"


def test_scan_form_file_upload(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    log_content = b"Ataque detectado desde 203.0.113.42 puerto 22"
    r = client.post(
        "/api/scan",
        files={"file": ("access.log", log_content, "text/plain")},
    )
    assert r.status_code == 200
    assert r.json()["ioc_value"] == "203.0.113.42"


def test_scan_form_file_no_iocs_returns_422(client):
    r = client.post(
        "/api/scan",
        files={"file": ("empty.log", b"sin ips ni hashes aqui", "text/plain")},
    )
    assert r.status_code == 422


def test_scan_form_no_input_returns_422(client):
    r = client.post("/api/scan")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Tests de GET /api/history y GET /api/history/{id}
# ---------------------------------------------------------------------------

def test_history_empty(client):
    r = client.get("/api/history")
    assert r.status_code == 200
    assert r.json() == []


def test_history_detail_not_found(client):
    r = client.get("/api/history/9999")
    assert r.status_code == 404


def test_history_detail_found(client, monkeypatch):
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)

    scan_r = client.post("/api/scan/json", json={"ioc": "1.2.3.4"})
    scan_id = scan_r.json()["id"]

    detail_r = client.get(f"/api/history/{scan_id}")
    assert detail_r.status_code == 200
    assert detail_r.json()["ioc_value"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# Tests de GET /api/sources
# ---------------------------------------------------------------------------

def test_sources_returns_list(client):
    r = client.get("/api/sources")
    assert r.status_code == 200
    sources = r.json()
    assert isinstance(sources, list)
    names = [s["name"] for s in sources]
    assert "virustotal" in names
    assert "abuseipdb" in names


def test_sources_has_availability_field(client):
    r = client.get("/api/sources")
    for source in r.json():
        assert "available" in source
        assert "supported_types" in source
