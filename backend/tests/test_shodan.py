import httpx
import pytest

from ioc_correlator.connectors.shodan import ShodanConnector
from ioc_correlator.utils.validators import IOCType

_RESP_SENSITIVE_PORTS = {
    "ports": [22, 80, 443, 3389],
    "hostnames": ["evil.example.com"],
    "country_name": "Russia",
    "org": "Bad AS",
    "vulns": {"CVE-2021-44228": {}, "CVE-2023-1234": {}},
}

_RESP_CLEAN = {
    "ports": [80, 443],
    "hostnames": ["cdn.example.com"],
    "country_name": "United States",
    "org": "Cloudflare Inc.",
    "vulns": {},
}

_RESP_NO_PORTS = {
    "ports": [],
    "hostnames": [],
    "country_name": "",
    "org": "",
    "vulns": {},
}

_RESP_MALFORMED = {"error": "unexpected_field_structure"}


@pytest.fixture()
def connector(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")
    return ShodanConnector()


# ---------------------------------------------------------------------------
# Support type tests
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
# _parse() tests
# ---------------------------------------------------------------------------

def test_parse_sensitive_ports(connector):
    result = connector._parse(_RESP_SENSITIVE_PORTS)
    assert result.success is True
    assert result.verdict == "suspicious"
    assert 22 in result.data["sensitive_ports"]
    assert 3389 in result.data["sensitive_ports"]
    assert len(result.data["vulns"]) == 2
    assert "sensibles" in result.summary


def test_parse_clean(connector):
    result = connector._parse(_RESP_CLEAN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["sensitive_ports"] == []
    assert "sensibles" not in result.summary


def test_parse_no_ports(connector):
    result = connector._parse(_RESP_NO_PORTS)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["open_ports"] == []


def test_parse_vulns_in_summary(connector):
    result = connector._parse(_RESP_SENSITIVE_PORTS)
    assert "CVE" in result.summary


def test_parse_malformed(connector):
    result = connector._parse(None)
    assert result.success is False
    assert result.error == "parse_error"


# ---------------------------------------------------------------------------
# query() error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_no_api_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    result = await ShodanConnector().query("1.2.3.4", IOCType.IPV4)
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
        req = httpx.Request("GET", "https://api.shodan.io/shodan/host/1.2.3.4")
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
