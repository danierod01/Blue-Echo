"""Tests del export SIEM/TI (roadmap I2): STIX 2.1 y MISP."""

import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from ioc_correlator.siem_export import to_misp, to_stix  # noqa: E402


def _make_scan(ioc_value="185.220.101.45", ioc_type="ipv4", verdict="critical", score=87):
    """Construye un objeto tipo ScanResponse mínimo para los tests."""
    return SimpleNamespace(
        id=1,
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        score=score,
        verdict=verdict,
        ai_summary="Nodo Tor malicioso.",
        created_at=datetime(2026, 9, 29, 8, 41, 2, tzinfo=timezone.utc),
        connector_results={
            "virustotal": SimpleNamespace(verdict="malicious"),
            "abuseipdb": SimpleNamespace(verdict="malicious"),
            "shodan": SimpleNamespace(verdict="suspicious"),
            "malwarebazaar": SimpleNamespace(verdict="clean"),
        },
        mitre_techniques=[
            SimpleNamespace(id="T1071", name="Application Layer Protocol", tactic="C2", reason="x"),
            SimpleNamespace(id="T1595", name="Active Scanning", tactic="Reconnaissance", reason="y"),
        ],
    )


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def test_stix_bundle_shape():
    bundle = to_stix(_make_scan())
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    ind = indicators[0]
    assert ind["spec_version"] == "2.1"
    assert ind["pattern_type"] == "stix"
    assert ind["pattern"] == "[ipv4-addr:value = '185.220.101.45']"
    assert ind["indicator_types"] == ["malicious-activity"]
    assert ind["confidence"] == 87
    assert ind["x_blue_echo_score"] == 87
    # Solo malicious/suspicious cuentan como fuentes positivas.
    assert set(ind["x_blue_echo_sources"]) == {"virustotal", "abuseipdb", "shodan"}


def test_stix_deterministic_indicator_id():
    a = to_stix(_make_scan())
    b = to_stix(_make_scan())
    id_a = next(o["id"] for o in a["objects"] if o["type"] == "indicator")
    id_b = next(o["id"] for o in b["objects"] if o["type"] == "indicator")
    assert id_a == id_b  # mismo IOC → mismo id (idempotente para el receptor)


def test_stix_mitre_attack_patterns_and_relationships():
    bundle = to_stix(_make_scan())
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(aps) == 2
    assert len(rels) == 2
    ext_ids = {ap["external_references"][0]["external_id"] for ap in aps}
    assert ext_ids == {"T1071", "T1595"}
    assert all(r["relationship_type"] == "indicates" for r in rels)


@pytest.mark.parametrize("ioc_type,value,expected", [
    ("domain", "evil.com", "[domain-name:value = 'evil.com']"),
    ("url", "http://evil.com/x", "[url:value = 'http://evil.com/x']"),
    ("md5", "d41d8cd98f00b204e9800998ecf8427e", "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"),
    ("sha256", "a" * 64, f"[file:hashes.'SHA-256' = '{'a' * 64}']"),
])
def test_stix_pattern_per_type(ioc_type, value, expected):
    bundle = to_stix(_make_scan(ioc_value=value, ioc_type=ioc_type))
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == expected


def test_stix_escapes_quotes():
    bundle = to_stix(_make_scan(ioc_value="a'b", ioc_type="domain"))
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[domain-name:value = 'a\\'b']"


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

def test_misp_event_shape():
    event = to_misp(_make_scan())["Event"]
    assert event["threat_level_id"] == 1        # critical → High
    assert event["date"] == "2026-09-29"
    assert len(event["Attribute"]) == 1
    attr = event["Attribute"][0]
    assert attr["type"] == "ip-dst"
    assert attr["value"] == "185.220.101.45"
    assert attr["to_ids"] is True


def test_misp_clean_verdict_not_actionable():
    event = to_misp(_make_scan(verdict="clean", score=5))["Event"]
    assert event["threat_level_id"] == 3        # clean → Low
    assert event["Attribute"][0]["to_ids"] is False


def test_misp_hash_attribute_type():
    event = to_misp(_make_scan(ioc_value="d" * 32, ioc_type="md5"))["Event"]
    assert event["Attribute"][0]["type"] == "md5"
    assert event["Attribute"][0]["category"] == "Payload delivery"


# ---------------------------------------------------------------------------
# Endpoint /api/history/{id}/export (ruta + aislamiento por token)
# ---------------------------------------------------------------------------

from main import app  # noqa: E402
from ioc_correlator.database import get_session, create_api_key, save_scan  # noqa: E402

# Resultado de conector serializable (formato que guarda _run_scan).
_CONN = {
    "virustotal": {
        "source": "virustotal", "success": True,
        "data": {"malicious": 23, "suspicious": 0, "total": 87, "stats": {}},
        "verdict": "malicious", "summary": "VT", "error": None,
    }
}


@pytest.fixture(name="session")
def _session():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture(name="client")
def _client(session):
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _seed_scan(session, api_key="tokenA", ioc="1.1.1.1"):
    """Inserta un escaneo directamente (evita la ruta /scan, que está
    rate-limited y agotaría su cupo global en la suite completa)."""
    scan = save_scan(session, ioc_value=ioc, ioc_type="ipv4", score=87,
                     verdict="critical", connector_results=_CONN,
                     ai_summary="Nodo Tor.", api_key=api_key)
    return scan.id


def test_export_endpoint_stix_and_misp(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="tokenA", label="Ana")
    scan_id = _seed_scan(session)

    stix = client.get(f"/api/history/{scan_id}/export?format=stix", headers={"X-API-Key": "tokenA"})
    assert stix.status_code == 200
    assert stix.json()["type"] == "bundle"

    misp = client.get(f"/api/history/{scan_id}/export?format=misp", headers={"X-API-Key": "tokenA"})
    assert misp.status_code == 200
    assert "Event" in misp.json()


def test_export_endpoint_isolated_and_validated(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="tokenA", label="Ana")
    create_api_key(session, key="tokenB", label="Bob")
    scan_id = _seed_scan(session, api_key="tokenA")

    # Token ajeno → 404 (mismo aislamiento que el resto del historial)
    ajeno = client.get(f"/api/history/{scan_id}/export", headers={"X-API-Key": "tokenB"})
    assert ajeno.status_code == 404

    # Formato inválido → 422 (validación del Query param)
    bad = client.get(f"/api/history/{scan_id}/export?format=csv", headers={"X-API-Key": "tokenA"})
    assert bad.status_code == 422
