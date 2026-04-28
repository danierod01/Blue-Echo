import httpx
import pytest

from ioc_correlator.connectors.otx import OTXConnector
from ioc_correlator.utils.validators import IOCType

_RESP_MALICIOUS = {
    "pulse_info": {
        "count": 5,
        "pulses": [
            {"tags": ["tor", "c2"]},
            {"tags": ["malware", "ransomware"]},
            {"tags": ["botnet"]},
        ],
    }
}

_RESP_CLEAN = {
    "pulse_info": {
        "count": 0,
        "pulses": [],
    }
}

_RESP_ONE_PULSE = {
    "pulse_info": {
        "count": 1,
        "pulses": [{"tags": ["phishing"]}],
    }
}

_RESP_NO_PULSE_INFO = {}

_RESP_MALFORMED = None


@pytest.fixture()
def connector(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")
    return OTXConnector()


# ---------------------------------------------------------------------------
# Support type tests
# ---------------------------------------------------------------------------

def test_supports_ipv4(connector):
    assert connector.supports(IOCType.IPV4) is True


def test_supports_ipv6(connector):
    assert connector.supports(IOCType.IPV6) is True


def test_supports_domain(connector):
    assert connector.supports(IOCType.DOMAIN) is True


def test_supports_sha256(connector):
    assert connector.supports(IOCType.SHA256) is True


def test_does_not_support_url(connector):
    assert connector.supports(IOCType.URL) is False


# ---------------------------------------------------------------------------
# _parse() tests
# ---------------------------------------------------------------------------

def test_parse_malicious(connector):
    result = connector._parse(_RESP_MALICIOUS)
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["pulse_count"] == 5
    assert "tor" in result.data["tags"] or "c2" in result.data["tags"]
    assert "5" in result.summary


def test_parse_clean(connector):
    result = connector._parse(_RESP_CLEAN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["pulse_count"] == 0


def test_parse_one_pulse(connector):
    result = connector._parse(_RESP_ONE_PULSE)
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["pulse_count"] == 1
    assert "1 pulso" in result.summary


def test_parse_no_pulse_info(connector):
    result = connector._parse(_RESP_NO_PULSE_INFO)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["pulse_count"] == 0


def test_parse_malformed(connector):
    result = connector._parse(_RESP_MALFORMED)
    assert result.success is False
    assert result.error == "parse_error"


# ---------------------------------------------------------------------------
# query() error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_no_api_key(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    result = await OTXConnector().query("1.2.3.4", IOCType.IPV4)
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
async def test_query_403(connector, monkeypatch):
    async def raise_403(ioc_value, ioc_type):
        req = httpx.Request("GET", "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general")
        resp = httpx.Response(403, request=req)
        raise httpx.HTTPStatusError("403", request=req, response=resp)

    monkeypatch.setattr(connector, "_fetch", raise_403)
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "http_403"


@pytest.mark.asyncio
async def test_query_unsupported_type(connector):
    result = await connector.query("https://evil.com/malware", IOCType.URL)
    assert result.success is False
    assert result.error == "unsupported_ioc_type"
