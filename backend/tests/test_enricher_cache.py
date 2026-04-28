"""Tests de integración de la caché en el enricher."""
import pytest

from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.enricher import enrich
from ioc_correlator.utils.cache import get_cache, reset_cache
from ioc_correlator.utils.validators import IOCType


@pytest.fixture(autouse=True)
def clean_cache():
    reset_cache()
    yield
    reset_cache()


def _fake_result(source: str) -> ConnectorResult:
    return ConnectorResult(
        source=source,
        success=True,
        data={},
        verdict="clean",
        summary=f"{source}: ok.",
    )


@pytest.mark.asyncio
async def test_cache_hit_skips_connectors(monkeypatch):
    """Si el IOC ya está en caché, enrich() devuelve el valor sin llamar a ningún conector."""
    call_count = 0

    async def fake_enrich_inner(ioc_value, ioc_type):
        nonlocal call_count
        call_count += 1
        return _fake_result("virustotal")

    # Precargar la caché manualmente
    cached_data = {"virustotal": _fake_result("virustotal")}
    get_cache().set(f"{IOCType.IPV4.value}:1.2.3.4", cached_data)

    result = await enrich("1.2.3.4", IOCType.IPV4)

    assert call_count == 0  # no se llamó a ningún conector
    assert "virustotal" in result
    assert result["virustotal"].verdict == "clean"


@pytest.mark.asyncio
async def test_cache_miss_stores_result(monkeypatch):
    """Tras una consulta real, el resultado se guarda en caché."""

    async def fake_query(ioc_value, ioc_type):
        return _fake_result("virustotal")

    # Mockear todos los conectores para que no hagan peticiones HTTP reales
    import ioc_correlator.enricher as enricher_mod
    original_connectors = enricher_mod._CONNECTORS

    class _FakeConnector:
        name = "virustotal"
        supported_types = [IOCType.IPV4]

        def supports(self, ioc_type):
            return ioc_type in self.supported_types

        async def query(self, ioc_value, ioc_type):
            return _fake_result(self.name)

    monkeypatch.setattr(enricher_mod, "_CONNECTORS", [_FakeConnector()])

    result = await enrich("9.9.9.9", IOCType.IPV4)
    assert "virustotal" in result

    # El resultado debe estar ahora en caché
    key = f"{IOCType.IPV4.value}:9.9.9.9"
    assert get_cache().get(key) is not None

    monkeypatch.setattr(enricher_mod, "_CONNECTORS", original_connectors)


@pytest.mark.asyncio
async def test_different_iocs_cached_separately(monkeypatch):
    """Dos IOCs distintos tienen entradas de caché independientes."""
    import ioc_correlator.enricher as enricher_mod

    class _FakeConnector:
        name = "virustotal"
        supported_types = [IOCType.IPV4]

        def supports(self, ioc_type):
            return ioc_type in self.supported_types

        async def query(self, ioc_value, ioc_type):
            return _fake_result(self.name)

    monkeypatch.setattr(enricher_mod, "_CONNECTORS", [_FakeConnector()])

    await enrich("1.1.1.1", IOCType.IPV4)
    await enrich("2.2.2.2", IOCType.IPV4)

    key1 = f"{IOCType.IPV4.value}:1.1.1.1"
    key2 = f"{IOCType.IPV4.value}:2.2.2.2"
    assert get_cache().get(key1) is not None
    assert get_cache().get(key2) is not None
    assert get_cache().get(key1) is not get_cache().get(key2)
