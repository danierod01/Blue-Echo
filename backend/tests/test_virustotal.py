import base64

import httpx
import pytest

from ioc_correlator.connectors.virustotal import VirusTotalConnector
from ioc_correlator.utils.validators import IOCType

# ---------------------------------------------------------------------------
# Respuestas de ejemplo que devuelve la API de VirusTotal v3
# ---------------------------------------------------------------------------

_VT_IP_MALICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 23,
                "suspicious": 0,
                "undetected": 60,
                "harmless": 4,
                "timeout": 0,
            }
        }
    }
}

_VT_IP_SUSPICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 3,
                "suspicious": 1,
                "undetected": 80,
                "harmless": 3,
                "timeout": 0,
            }
        }
    }
}

_VT_IP_CLEAN = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 10,
                "harmless": 77,
                "timeout": 0,
            }
        }
    }
}

_VT_HASH = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 60,
                "suspicious": 2,
                "undetected": 10,
                "harmless": 0,
                "timeout": 0,
            },
            "meaningful_name": "trojan.genericKD",
        }
    }
}

_VT_MALFORMED = {"unexpected": "schema"}


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def connector(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    return VirusTotalConnector()


# ---------------------------------------------------------------------------
# Tests de _endpoint() — lógica pura, sin HTTP
# ---------------------------------------------------------------------------

def test_endpoint_ipv4(connector):
    url = connector._endpoint("1.2.3.4", IOCType.IPV4)
    assert url == "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"


def test_endpoint_ipv6(connector):
    url = connector._endpoint("::1", IOCType.IPV6)
    assert url == "https://www.virustotal.com/api/v3/ip_addresses/::1"


def test_endpoint_md5(connector):
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert connector._endpoint(h, IOCType.MD5) == f"https://www.virustotal.com/api/v3/files/{h}"


def test_endpoint_sha256(connector):
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert connector._endpoint(h, IOCType.SHA256) == f"https://www.virustotal.com/api/v3/files/{h}"


def test_endpoint_domain(connector):
    assert connector._endpoint("evil.com", IOCType.DOMAIN) == \
        "https://www.virustotal.com/api/v3/domains/evil.com"


def test_endpoint_url_uses_base64(connector):
    raw = "https://evil.com/payload.exe"
    expected_id = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    url = connector._endpoint(raw, IOCType.URL)
    assert url == f"https://www.virustotal.com/api/v3/urls/{expected_id}"


# ---------------------------------------------------------------------------
# Tests de _parse() — lógica pura, sin HTTP
# ---------------------------------------------------------------------------

def test_parse_malicious(connector):
    result = connector._parse(_VT_IP_MALICIOUS, "1.2.3.4")
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["malicious"] == 23
    assert result.data["total"] == 87
    assert "23/87" in result.summary


def test_parse_suspicious(connector):
    result = connector._parse(_VT_IP_SUSPICIOUS, "1.2.3.4")
    assert result.success is True
    assert result.verdict == "suspicious"


def test_parse_clean(connector):
    result = connector._parse(_VT_IP_CLEAN, "1.2.3.4")
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["malicious"] == 0


def test_parse_hash(connector):
    result = connector._parse(_VT_HASH, "d41d8cd98f00b204e9800998ecf8427e")
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["malicious"] == 60


def test_parse_malformed_response(connector):
    result = connector._parse(_VT_MALFORMED, "1.2.3.4")
    assert result.success is False
    assert result.error == "parse_error"


def test_parse_empty_stats(connector):
    body = {"data": {"attributes": {"last_analysis_stats": {}}}}
    result = connector._parse(body, "1.2.3.4")
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["total"] == 0


# ---------------------------------------------------------------------------
# Tests de query() — manejo de errores HTTP (monkeypatching _fetch)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_timeout(connector, monkeypatch):
    async def fake_fetch(ioc_value, ioc_type):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(connector, "_fetch", fake_fetch)
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "timeout"


@pytest.mark.asyncio
async def test_query_rate_limit(connector, monkeypatch):
    async def fake_fetch(ioc_value, ioc_type):
        req = httpx.Request("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4")
        resp = httpx.Response(429, request=req)
        raise httpx.HTTPStatusError("429", request=req, response=resp)

    monkeypatch.setattr(connector, "_fetch", fake_fetch)
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "http_429"
    assert "rate limit" in result.summary.lower()


@pytest.mark.asyncio
async def test_query_no_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    connector = VirusTotalConnector()
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "missing_api_key"


@pytest.mark.asyncio
async def test_query_unsupported_type(connector):
    # VirusTotal soporta todos los tipos, forzamos uno inválido directamente
    from ioc_correlator.utils.validators import IOCType as T
    # Creamos un conector con supported_types reducidos para el test
    connector.supported_types = [IOCType.IPV4]
    result = await connector.query("evil.com", IOCType.DOMAIN)
    assert result.success is False
    assert result.error == "unsupported_ioc_type"
