"""Tests de la generación de reglas de bloqueo/respuesta (detección → respuesta)."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from ioc_correlator.response_actions import generate_block_rules  # noqa: E402
from ioc_correlator.utils.validators import IOCType  # noqa: E402
from ioc_correlator.database import get_session, save_scan  # noqa: E402


# ---------------------------------------------------------------------------
# Generación pura
# ---------------------------------------------------------------------------

def test_ip_rules_cover_expected_formats():
    rules = generate_block_rules("1.2.3.4", IOCType.IPV4, verdict="malicious", score=90)
    for fmt in ("iptables", "nftables", "pf", "cisco", "windows"):
        assert fmt in rules
    assert "iptables -A INPUT  -s 1.2.3.4 -j DROP" in rules["iptables"]
    assert "block drop quick from 1.2.3.4 to any" in rules["pf"]
    assert "deny ip host 1.2.3.4 any" in rules["cisco"]
    # cabecera de procedencia con metadatos
    assert "Blue-Echo" in rules["iptables"]
    assert "veredicto=malicious score=90" in rules["iptables"]


def test_ipv6_uses_ip6tables():
    rules = generate_block_rules("2001:db8::1", IOCType.IPV6)
    assert "ip6tables -A INPUT" in rules["iptables"]


def test_domain_rules():
    rules = generate_block_rules("evil.com", IOCType.DOMAIN)
    assert "0.0.0.0 evil.com" in rules["hosts"]
    assert 'always_nxdomain' in rules["unbound"]
    assert "pihole -b evil.com" in rules["pihole"]
    # no debe ofrecer reglas de firewall de IP para un dominio
    assert "iptables" not in rules


def test_url_rules_extract_host_and_proxy():
    rules = generate_block_rules("http://malware.test/payload.exe", IOCType.URL)
    assert "0.0.0.0 malware.test" in rules["hosts"]
    assert "dstdomain malware.test" in rules["squid"]


def test_url_with_ip_host_uses_firewall():
    rules = generate_block_rules("http://1.2.3.4/x", IOCType.URL)
    assert "iptables" in rules
    assert "1.2.3.4" in rules["iptables"]


def test_hash_gives_note_not_firewall():
    rules = generate_block_rules("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5)
    assert "note" in rules
    assert "iptables" not in rules
    assert "EDR" in rules["note"]


def test_type_autodetected_and_defanged():
    # sin pasar tipo, y con IOC neutralizado
    rules = generate_block_rules("1[.]2[.]3[.]4")
    assert "iptables" in rules
    assert "1.2.3.4" in rules["iptables"]


# ---------------------------------------------------------------------------
# Endpoint GET /history/{id}/blocklist
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


def test_blocklist_endpoint(client, session):
    s = save_scan(session, ioc_value="1.2.3.4", ioc_type="ipv4", score=90,
                  verdict="critical", connector_results={}, ai_summary="", api_key=None)
    r = client.get(f"/api/history/{s.id}/blocklist")
    assert r.status_code == 200
    body = r.json()
    assert body["ioc"] == "1.2.3.4"
    assert body["ioc_type"] == "ipv4"
    assert "iptables" in body["formats"]


def test_blocklist_endpoint_not_found(client):
    assert client.get("/api/history/9999/blocklist").status_code == 404


def test_blocklist_endpoint_isolation(client, session):
    s = save_scan(session, ioc_value="9.9.9.9", ioc_type="ipv4", score=10,
                  verdict="clean", connector_results={}, ai_summary="", api_key="otro")
    # sin cabecera de API key el override deja current_key="" → maestro ve todo;
    # con una clave distinta, el escaneo ajeno es 404.
    r = client.get(f"/api/history/{s.id}/blocklist", headers={"X-API-Key": "mia"})
    assert r.status_code == 404
