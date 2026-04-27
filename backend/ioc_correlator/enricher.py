import asyncio
import os

from ioc_correlator.connectors.abuseipdb import AbuseIPDBConnector
from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.connectors.virustotal import VirusTotalConnector
from ioc_correlator.utils.validators import IOCType

# Conectores activos. Los de los módulos 14 se añaden aquí cuando estén listos.
_CONNECTORS = [
    VirusTotalConnector(),
    AbuseIPDBConnector(),
]


async def enrich(
    ioc_value: str,
    ioc_type: IOCType,
) -> dict[str, ConnectorResult]:
    """Ejecuta en paralelo todos los conectores que soportan el tipo de IOC.

    Usa un semáforo para respetar MAX_CONCURRENT_REQUESTS. Si un conector
    falla (excepción no controlada), se captura y se registra como error
    sin interrumpir el resto.
    """
    max_concurrent = int(os.getenv("MAX_CONCURRENT_REQUESTS", 5))
    sem = asyncio.Semaphore(max_concurrent)

    active = [c for c in _CONNECTORS if c.supports(ioc_type)]

    async def _run(connector) -> ConnectorResult:
        async with sem:
            return await connector.query(ioc_value, ioc_type)

    results: list[ConnectorResult] = await asyncio.gather(
        *[_run(c) for c in active],
        return_exceptions=False,
    )
    return {r.source: r for r in results}


def get_sources_status() -> list[dict]:
    """Devuelve el estado de todos los conectores registrados."""
    return [
        {
            "name": c.name,
            "available": c.is_available(),
            "supported_types": [t.value for t in c.supported_types],
        }
        for c in _CONNECTORS
    ]
