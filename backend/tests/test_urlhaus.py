import httpx
import pytest

from ioc_correlator.connectors.urlhaus import URLhausConnector
from ioc_correlator.utils.validators import IOCType

_RESP_URL_ONLINE = {"query_status": "is_online"}
_RESP_URL_WAS_ONLINE = {"query_status": "was_online"}
_RESP_URL_CLEAN = {"query_status": "no_results"}

_RESP_HOST_MALICIOUS = {"query_status": "ok", "urls_count": 5}
_RESP_HOST_CLEAN = {"query_status": "no_results", "urls_count": 0}
_RESP_HOST_FOUND_NO_URLS = {"query_status": "ok", "urls_count": 0}

_RESP_MALFORMED = None


@pytest.fixture()
def connector():
    return URLhausConnector()


# ---------------------------------------------------------------------------
# Support type tests
# ---------------------------------------------------------------------------

def test_supports_url(connector):
    assert connector.supports(IOCType.URL) is True


def test_supports_domain(connector):
    assert connector.supports(IOCType.DOMAIN) is True


def test_does_not_support_ip(connector):
    assert connector.supports(IOCType.IPV4) is False


def test_does_not_support_hash(connector):
    assert connector.supports(IOCType.SHA256) is False


def test_no_api_key_needed(connector):
    assert connector.api_key_env is None


# ---------------------------------------------------------------------------
# _parse() tests — URL endpoint
# ---------------------------------------------------------------------------

def test_parse_url_online(connector):
    result = connector._parse(_RESP_URL_ONLINE, IOCType.URL)
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["found"] is True
    assert "activa" in result.summary


def test_parse_url_was_online(connector):
    result = connector._parse(_RESP_URL_WAS_ONLINE, IOCType.URL)
    assert result.success is True
    assert result.verdict == "suspicious"
    assert result.data["found"] is True
    assert "inactiva" in result.summary


def test_parse_url_clean(connector):
    result = connector._parse(_RESP_URL_CLEAN, IOCType.URL)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["found"] is False


# ---------------------------------------------------------------------------
# _parse() tests — Host/Domain endpoint
# ---------------------------------------------------------------------------

def test_parse_host_malicious(connector):
    result = connector._parse(_RESP_HOST_MALICIOUS, IOCType.DOMAIN)
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["urls_count"] == 5


def test_parse_host_clean(connector):
    result = connector._parse(_RESP_HOST_CLEAN, IOCType.DOMAIN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["found"] is False


def test_parse_host_found_zero_urls(connector):
    result = connector._parse(_RESP_HOST_FOUND_NO_URLS, IOCType.DOMAIN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["urls_count"] == 0


def test_parse_malformed(connector):
    result = connector._parse(_RESP_MALFORMED, IOCType.URL)
    assert result.success is False
    assert result.error == "parse_error"


# ---------------------------------------------------------------------------
# query() error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_timeout(connector, monkeypatch):
    async def raise_timeout(ioc_value, ioc_type):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(connector, "_fetch", raise_timeout)
    result = await connector.query("https://evil.com/malware.exe", IOCType.URL)
    assert result.success is False
    assert result.error == "timeout"


@pytest.mark.asyncio
async def test_query_429(connector, monkeypatch):
    async def raise_429(ioc_value, ioc_type):
        req = httpx.Request("POST", "https://urlhaus-api.abuse.ch/v1/url/")
        resp = httpx.Response(429, request=req)
        raise httpx.HTTPStatusError("429", request=req, response=resp)

    monkeypatch.setattr(connector, "_fetch", raise_429)
    result = await connector.query("https://evil.com/malware.exe", IOCType.URL)
    assert result.success is False
    assert result.error == "http_429"


@pytest.mark.asyncio
async def test_query_unsupported_type(connector):
    result = await connector.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "unsupported_ioc_type"
