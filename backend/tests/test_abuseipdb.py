import httpx
import pytest

from ioc_correlator.connectors.abuseipdb import AbuseIPDBConnector
from ioc_correlator.utils.validators import IOCType

# ---------------------------------------------------------------------------
# Respuestas de ejemplo de la API v2 de AbuseIPDB
# ---------------------------------------------------------------------------

_RESP_MALICIOUS = {
    "data": {
        "ipAddress": "185.220.101.45",
        "abuseConfidenceScore": 95,
        "totalReports": 142,
        "countryCode": "DE",
        "isp": "Tor Exit Node ISP",
        "lastReportedAt": "2026-04-27T08:00:00+00:00",
        "isWhitelisted": False,
    }
}

_RESP_SUSPICIOUS = {
    "data": {
        "ipAddress": "10.0.0.1",
        "abuseConfidenceScore": 65,
        "totalReports": 12,
        "countryCode": "US",
        "isp": "Some ISP",
        "lastReportedAt": "2026-01-01T00:00:00+00:00",
        "isWhitelisted": False,
    }
}

_RESP_LOW_CONFIDENCE = {
    "data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 10,
        "totalReports": 2,
        "countryCode": "US",
        "isp": "Google LLC",
        "lastReportedAt": None,
        "isWhitelisted": False,
    }
}

_RESP_CLEAN = {
    "data": {
        "ipAddress": "1.1.1.1",
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "countryCode": "AU",
        "isp": "Cloudflare",
        "lastReportedAt": None,
        "isWhitelisted": False,
    }
}

_RESP_WHITELISTED = {
    "data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 5,
        "totalReports": 1,
        "countryCode": "US",
        "isp": "Google LLC",
        "lastReportedAt": None,
        "isWhitelisted": True,
    }
}

_RESP_MALFORMED = {"error": "unexpected"}


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def connector(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    return AbuseIPDBConnector()


# ---------------------------------------------------------------------------
# Tests de soporte de tipos de IOC
# ---------------------------------------------------------------------------

def test_supports_ipv4(connector):
    assert connector.supports(IOCType.IPV4) is True


def test_supports_ipv6(connector):
    assert connector.supports(IOCType.IPV6) is True


def test_does_not_support_domain(connector):
    assert connector.supports(IOCType.DOMAIN) is False


def test_does_not_support_hash(connector):
    assert connector.supports(IOCType.SHA256) is False


# ---------------------------------------------------------------------------
# Tests de _parse() — lógica pura
# ---------------------------------------------------------------------------

def test_parse_malicious(connector):
    result = connector._parse(_RESP_MALICIOUS, "185.220.101.45")
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["confidence"] == 95
    assert result.data["total_reports"] == 142
    assert result.data["country"] == "DE"
    assert "95%" in result.summary


def test_parse_suspicious(connector):
    result = connector._parse(_RESP_SUSPICIOUS, "10.0.0.1")
    assert result.success is True
    assert result.verdict == "suspicious"
    assert result.data["confidence"] == 65


def test_parse_low_confidence_is_suspicious(connector):
    result = connector._parse(_RESP_LOW_CONFIDENCE, "8.8.8.8")
    assert result.success is True
    assert result.verdict == "suspicious"


def test_parse_clean(connector):
    result = connector._parse(_RESP_CLEAN, "1.1.1.1")
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["confidence"] == 0


def test_parse_whitelisted_overrides_score(connector):
    result = connector._parse(_RESP_WHITELISTED, "8.8.8.8")
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["is_whitelisted"] is True


def test_parse_null_last_reported(connector):
    result = connector._parse(_RESP_CLEAN, "1.1.1.1")
    assert result.data["last_reported"] == "nunca"


def test_parse_malformed(connector):
    result = connector._parse(_RESP_MALFORMED, "1.2.3.4")
    assert result.success is False
    assert result.error == "parse_error"


# ---------------------------------------------------------------------------
# Tests de query() — manejo de errores HTTP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_no_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = await AbuseIPDBConnector().query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "missing_api_key"


@pytest.mark.asyncio
async def test_query_timeout(connector, monkeypatch):
    async def raise_timeout(ioc_value, ioc_type):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(connector, "_fetch", raise_timeout)
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "timeout"


@pytest.mark.asyncio
async def test_query_429(connector, monkeypatch):
    async def raise_429(ioc_value, ioc_type):
        req = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
        resp = httpx.Response(429, request=req)
        raise httpx.HTTPStatusError("429", request=req, response=resp)

    monkeypatch.setattr(connector, "_fetch", raise_429)
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "http_429"


@pytest.mark.asyncio
async def test_query_unsupported_type(connector):
    result = await connector.query("evil.com", IOCType.DOMAIN)
    assert result.success is False
    assert result.error == "unsupported_ioc_type"
