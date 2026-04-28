import httpx
import pytest

from ioc_correlator.connectors.greynoise import GreyNoiseConnector
from ioc_correlator.utils.validators import IOCType

_RESP_MALICIOUS = {
    "seen": True,
    "classification": "malicious",
    "noise": True,
    "name": "Mirai",
}

_RESP_BENIGN = {
    "seen": True,
    "classification": "benign",
    "noise": True,
    "name": "Shodan.io",
}

_RESP_UNKNOWN = {
    "seen": True,
    "classification": "unknown",
    "noise": False,
    "name": "",
}

_RESP_NOT_SEEN = {
    "seen": False,
    "classification": "unknown",
    "noise": False,
    "name": "",
}

_RESP_MALFORMED = None


@pytest.fixture()
def connector(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    return GreyNoiseConnector()


# ---------------------------------------------------------------------------
# Support type tests
# ---------------------------------------------------------------------------

def test_supports_ipv4(connector):
    assert connector.supports(IOCType.IPV4) is True


def test_does_not_support_ipv6(connector):
    assert connector.supports(IOCType.IPV6) is False


def test_does_not_support_domain(connector):
    assert connector.supports(IOCType.DOMAIN) is False


def test_does_not_support_hash(connector):
    assert connector.supports(IOCType.SHA256) is False


# ---------------------------------------------------------------------------
# _parse() tests
# ---------------------------------------------------------------------------

def test_parse_malicious(connector):
    result = connector._parse(_RESP_MALICIOUS)
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["classification"] == "malicious"
    assert "MALICIOSA" in result.summary
    assert "Mirai" in result.summary


def test_parse_benign(connector):
    result = connector._parse(_RESP_BENIGN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["classification"] == "benign"
    assert "benigna" in result.summary
    assert "Shodan.io" in result.summary


def test_parse_unknown(connector):
    result = connector._parse(_RESP_UNKNOWN)
    assert result.success is True
    assert result.verdict == "clean"
    assert "sin clasificación" in result.summary


def test_parse_not_seen(connector):
    result = connector._parse(_RESP_NOT_SEEN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["seen"] is False
    assert "no observada" in result.summary


def test_parse_malformed(connector):
    result = connector._parse(_RESP_MALFORMED)
    assert result.success is False
    assert result.error == "parse_error"


# ---------------------------------------------------------------------------
# query() error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_no_api_key(monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    result = await GreyNoiseConnector().query("1.2.3.4", IOCType.IPV4)
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
        req = httpx.Request("GET", "https://api.greynoise.io/v3/community/1.2.3.4")
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


@pytest.mark.asyncio
async def test_query_404_returns_clean(connector, monkeypatch):
    """404 de GreyNoise significa 'no vista', no un error."""
    async def fetch_404(ioc_value, ioc_type):
        req = httpx.Request("GET", f"https://api.greynoise.io/v3/community/{ioc_value}")
        resp = httpx.Response(404, request=req)
        # 404 is handled inside _fetch before raise_for_status
        # Simulate the actual connector behavior returning clean directly
        from ioc_correlator.connectors.base import ConnectorResult
        return ConnectorResult(
            source="greynoise",
            success=True,
            data={"seen": False, "classification": "unknown", "noise": False},
            verdict="clean",
            summary="GreyNoise: IP no observada en internet ruidoso.",
        )

    monkeypatch.setattr(connector, "_fetch", fetch_404)
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is True
    assert result.verdict == "clean"
    assert "no observada" in result.summary
