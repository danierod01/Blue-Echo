"""Tests de la generación de reglas de detección (Sigma / Suricata / YARA)."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from ioc_correlator.detection_rules import generate_detection_rules  # noqa: E402
from ioc_correlator.utils.validators import IOCType  # noqa: E402
from ioc_correlator.database import get_session, save_scan  # noqa: E402


def test_ip_rules_sigma_and_suricata():
    rules = generate_detection_rules("1.2.3.4", IOCType.IPV4, score=90)
    assert set(rules) == {"sigma", "suricata"}
    assert "dst_ip:" in rules["sigma"]
    assert "1.2.3.4" in rules["sigma"]
    assert "level: critical" in rules["sigma"]         # score 90 → critical
    assert "alert ip any any -> 1.2.3.4 any" in rules["suricata"]
    assert "sid:" in rules["suricata"]


def test_domain_rules():
    rules = generate_detection_rules("evil.com", IOCType.DOMAIN, score=60)
    assert "category: dns_query" in rules["sigma"]
    assert "level: high" in rules["sigma"]              # score 60 → high
    assert 'dns.query; content:"evil.com"' in rules["suricata"]
    assert "yara" not in rules


def test_url_rules_split_host_and_path():
    rules = generate_detection_rules("http://malware.test/payload.exe", IOCType.URL)
    assert "c-uri|contains:" in rules["sigma"]
    assert 'http.host; content:"malware.test"' in rules["suricata"]
    assert 'http.uri; content:"/payload.exe"' in rules["suricata"]


def test_hash_gives_yara_and_sigma_not_suricata():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    rules = generate_detection_rules(h, IOCType.MD5)
    assert "yara" in rules and "sigma" in rules
    assert "suricata" not in rules
    assert 'import "hash"' in rules["yara"]
    assert f'hash.md5(0, filesize) == "{h}"' in rules["yara"]
    assert "Hashes|contains:" in rules["sigma"]
    assert f"MD5={h}" in rules["sigma"]


def test_ids_are_deterministic():
    a = generate_detection_rules("1.2.3.4", IOCType.IPV4)
    b = generate_detection_rules("1.2.3.4", IOCType.IPV4)
    assert a == b                                       # mismos IDs/SIDs → no duplica al reimportar


def test_autodetect_and_defang():
    rules = generate_detection_rules("evil[dot]com")
    assert "evil.com" in rules["sigma"]


def test_unknown_returns_empty():
    assert generate_detection_rules("no-es-un-ioc-valido !!") == {}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

from main import app  # noqa: E402


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


def test_detection_rules_endpoint(client, session):
    s = save_scan(session, ioc_value="1.2.3.4", ioc_type="ipv4", score=90,
                  verdict="critical", connector_results={}, ai_summary="", api_key=None)
    r = client.get(f"/api/history/{s.id}/detection-rules")
    assert r.status_code == 200
    body = r.json()
    assert body["ioc"] == "1.2.3.4"
    assert "sigma" in body["formats"] and "suricata" in body["formats"]


def test_detection_rules_endpoint_not_found(client):
    assert client.get("/api/history/9999/detection-rules").status_code == 404


def test_detection_rules_endpoint_isolation(client, session):
    s = save_scan(session, ioc_value="9.9.9.9", ioc_type="ipv4", score=10,
                  verdict="clean", connector_results={}, ai_summary="", api_key="otro")
    r = client.get(f"/api/history/{s.id}/detection-rules", headers={"X-API-Key": "mia"})
    assert r.status_code == 404
