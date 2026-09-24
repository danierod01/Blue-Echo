import httpx
import pytest

from ioc_correlator.connectors.greynoise import GreyNoiseConnector
from ioc_correlator.scorer import _score_greynoise
from ioc_correlator.utils.validators import IOCType

# ---------------------------------------------------------------------------
# Respuestas de ejemplo de la Community API de GreyNoise
# ---------------------------------------------------------------------------

_RESP_MALICIOUS = {
    "ip": "185.220.101.45",
    "noise": True,
    "riot": False,
    "classification": "malicious",
    "name": "Tor Exit Node",
    "last_seen": "2026-09-20",
    "message": "Success",
}

_RESP_BENIGN = {
    "ip": "8.8.8.8",
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "Google Public DNS",
    "last_seen": "2026-09-21",
    "message": "Success",
}

_RESP_NOISE_UNKNOWN = {
    "ip": "45.33.32.156",
    "noise": True,
    "riot": False,
    "classification": "unknown",
    "name": "",
    "last_seen": "2026-09-19",
    "message": "Success",
}

# Forma inesperada: la API devuelve una lista en vez de un objeto
_RESP_MALFORMED = ["unexpected", "shape"]


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def connector(monkeypatch):
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    return GreyNoiseConnector()


# ---------------------------------------------------------------------------
# Soporte de tipos de IOC
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
# _parse() — lógica pura
# ---------------------------------------------------------------------------

def test_parse_malicious(connector):
    result = connector._parse(_RESP_MALICIOUS)
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.data["classification"] == "malicious"
    assert result.data["seen"] is True
    assert "maliciosa" not in result.summary  # summary usa la clasificación cruda
    assert "malicious" in result.summary


def test_parse_benign(connector):
    result = connector._parse(_RESP_BENIGN)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["riot"] is True
    assert "RIOT" in result.summary


def test_parse_noise_unknown_is_suspicious(connector):
    result = connector._parse(_RESP_NOISE_UNKNOWN)
    assert result.success is True
    assert result.verdict == "suspicious"


def test_parse_malformed(connector):
    result = connector._parse(_RESP_MALFORMED)
    assert result.success is False
    assert result.error == "parse_error"


# ---------------------------------------------------------------------------
# Reglas de scoring (+30 malicious, -10 benign)
# ---------------------------------------------------------------------------

def test_score_malicious(connector):
    assert _score_greynoise(connector._parse(_RESP_MALICIOUS)) == 30


def test_score_benign(connector):
    assert _score_greynoise(connector._parse(_RESP_BENIGN)) == -10


def test_score_unknown(connector):
    assert _score_greynoise(connector._parse(_RESP_NOISE_UNKNOWN)) == 0


# ---------------------------------------------------------------------------
# query() end-to-end con mocks HTTP (httpx.MockTransport)
# ---------------------------------------------------------------------------

def _mock_connector(monkeypatch, handler):
    """Devuelve un GreyNoiseConnector cuyo cliente HTTP usa un transporte mock."""
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")
    conn = GreyNoiseConnector()

    def make_mock_client():
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(conn, "_make_client", make_mock_client)
    return conn


@pytest.mark.asyncio
async def test_query_malicious(monkeypatch):
    conn = _mock_connector(
        monkeypatch, lambda req: httpx.Response(200, json=_RESP_MALICIOUS)
    )
    result = await conn.query("185.220.101.45", IOCType.IPV4)
    assert result.success is True
    assert result.verdict == "malicious"


@pytest.mark.asyncio
async def test_query_404_is_not_error(monkeypatch):
    # 404 en la Community API = IP no observada, no un fallo del conector
    conn = _mock_connector(
        monkeypatch, lambda req: httpx.Response(404, json={"message": "IP not observed"})
    )
    result = await conn.query("1.1.1.1", IOCType.IPV4)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data["seen"] is False


@pytest.mark.asyncio
async def test_query_429(monkeypatch):
    conn = _mock_connector(monkeypatch, lambda req: httpx.Response(429, json={}))
    result = await conn.query("8.8.8.8", IOCType.IPV4)
    assert result.success is False
    assert result.error == "http_429"


@pytest.mark.asyncio
async def test_query_no_api_key(monkeypatch):
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    result = await GreyNoiseConnector().query("8.8.8.8", IOCType.IPV4)
    assert result.success is False
    assert result.error == "missing_api_key"


@pytest.mark.asyncio
async def test_query_unsupported_type(connector):
    result = await connector.query("evil.com", IOCType.DOMAIN)
    assert result.success is False
    assert result.error == "unsupported_ioc_type"
