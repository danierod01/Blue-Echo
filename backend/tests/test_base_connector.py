import pytest
import httpx

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType


# ---------------------------------------------------------------------------
# Conector mínimo para los tests
# ---------------------------------------------------------------------------

class DummyConnector(BaseConnector):
    name = "dummy"
    supported_types = [IOCType.IPV4, IOCType.DOMAIN]
    api_key_env = "DUMMY_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(f"https://dummy.api/check/{ioc_value}")
            resp.raise_for_status()
            data = resp.json()
            return ConnectorResult(
                source=self.name,
                success=True,
                data=data,
                verdict="clean",
                summary="OK",
            )


class PublicConnector(BaseConnector):
    """Conector sin API key (como MalwareBazaar)."""
    name = "public"
    supported_types = [IOCType.MD5]
    api_key_env = None

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        return ConnectorResult(source=self.name, success=True, verdict="clean", summary="OK")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def connector_with_key(monkeypatch):
    monkeypatch.setenv("DUMMY_API_KEY", "test-key-123")
    return DummyConnector()


@pytest.fixture()
def connector_without_key(monkeypatch):
    monkeypatch.delenv("DUMMY_API_KEY", raising=False)
    return DummyConnector()


# ---------------------------------------------------------------------------
# Tests de estado del conector
# ---------------------------------------------------------------------------

def test_is_available_with_key(connector_with_key):
    assert connector_with_key.is_available() is True


def test_is_available_without_key(connector_without_key):
    assert connector_without_key.is_available() is False


def test_public_connector_always_available():
    assert PublicConnector().is_available() is True


def test_supports_true(connector_with_key):
    assert connector_with_key.supports(IOCType.IPV4) is True


def test_supports_false(connector_with_key):
    assert connector_with_key.supports(IOCType.SHA256) is False


# ---------------------------------------------------------------------------
# Tests de query() sin API key → retorno inmediato sin HTTP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_returns_error_when_no_key(connector_without_key):
    result = await connector_without_key.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "missing_api_key"
    assert result.source == "dummy"


@pytest.mark.asyncio
async def test_query_returns_error_for_unsupported_type(connector_with_key):
    result = await connector_with_key.query("abc123", IOCType.SHA256)
    assert result.success is False
    assert result.error == "unsupported_ioc_type"


# ---------------------------------------------------------------------------
# Tests de manejo de errores HTTP (con respx)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_handles_timeout(connector_with_key, monkeypatch):
    async def raise_timeout(ioc_value, ioc_type):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(connector_with_key, "_fetch", raise_timeout)
    result = await connector_with_key.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "timeout"


@pytest.mark.asyncio
async def test_query_handles_429(connector_with_key, monkeypatch):
    async def raise_429(ioc_value, ioc_type):
        response = httpx.Response(429, request=httpx.Request("GET", "https://dummy.api/"))
        raise httpx.HTTPStatusError("429", request=response.request, response=response)

    monkeypatch.setattr(connector_with_key, "_fetch", raise_429)
    result = await connector_with_key.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "http_429"
    assert "rate limit" in result.summary.lower()


@pytest.mark.asyncio
async def test_query_handles_403(connector_with_key, monkeypatch):
    async def raise_403(ioc_value, ioc_type):
        response = httpx.Response(403, request=httpx.Request("GET", "https://dummy.api/"))
        raise httpx.HTTPStatusError("403", request=response.request, response=response)

    monkeypatch.setattr(connector_with_key, "_fetch", raise_403)
    result = await connector_with_key.query("1.2.3.4", IOCType.IPV4)
    assert result.success is False
    assert result.error == "http_403"
    assert "api key" in result.summary.lower()


@pytest.mark.asyncio
async def test_query_success(connector_with_key, monkeypatch):
    expected = ConnectorResult(
        source="dummy",
        success=True,
        data={"malicious": False},
        verdict="clean",
        summary="OK",
    )

    async def fake_fetch(ioc_value, ioc_type):
        return expected

    monkeypatch.setattr(connector_with_key, "_fetch", fake_fetch)
    result = await connector_with_key.query("1.2.3.4", IOCType.IPV4)
    assert result.success is True
    assert result.verdict == "clean"
    assert result.data == {"malicious": False}
