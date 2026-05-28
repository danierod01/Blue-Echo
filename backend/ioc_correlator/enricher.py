import asyncio
import logging
import os

from ioc_correlator.connectors.abuseipdb import AbuseIPDBConnector
from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.connectors.censys import CensysConnector
from ioc_correlator.connectors.criminal_ip import CriminalIPConnector
from ioc_correlator.connectors.hybrid_analysis import HybridAnalysisConnector
from ioc_correlator.connectors.ipinfo import IPinfoConnector
from ioc_correlator.connectors.malshare import MalShareConnector
from ioc_correlator.connectors.malwarebazaar import MalwareBazaarConnector
from ioc_correlator.connectors.netlas import NetlasConnector
from ioc_correlator.connectors.otx import OTXConnector
from ioc_correlator.connectors.pulsedive import PulsediveConnector
from ioc_correlator.connectors.rdap import RDAPConnector
from ioc_correlator.connectors.securitytrails import SecurityTrailsConnector
from ioc_correlator.connectors.shodan import ShodanConnector
from ioc_correlator.connectors.threatfox import ThreatFoxConnector
from ioc_correlator.connectors.urlhaus import URLhausConnector
from ioc_correlator.connectors.virustotal import VirusTotalConnector
from ioc_correlator.utils.cache import get_cache
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_CONNECTORS = [
    # Fuentes originales
    VirusTotalConnector(),
    AbuseIPDBConnector(),
    ShodanConnector(),
    OTXConnector(),
    MalwareBazaarConnector(),
    URLhausConnector(),
    # Nuevas fuentes
    ThreatFoxConnector(),
    IPinfoConnector(),
    SecurityTrailsConnector(),
    HybridAnalysisConnector(),
    NetlasConnector(),
    CriminalIPConnector(),
    MalShareConnector(),
    PulsediveConnector(),
    CensysConnector(),
    RDAPConnector(),
]


def _cache_key(ioc_value: str, ioc_type: IOCType) -> str:
    return f"{ioc_type.value}:{ioc_value}"


async def enrich(
    ioc_value: str,
    ioc_type: IOCType,
) -> dict[str, ConnectorResult]:
    """Ejecuta en paralelo todos los conectores que soportan el tipo de IOC.

    Comprueba la caché antes de lanzar las peticiones. Si el IOC ya fue
    consultado recientemente, devuelve el resultado almacenado sin llamar
    a ninguna API externa. El TTL se configura con CACHE_TTL_SECONDS (por
    defecto 3600 segundos).

    Usa un semáforo para respetar MAX_CONCURRENT_REQUESTS.
    """
    key = _cache_key(ioc_value, ioc_type)
    cached = get_cache().get(key)
    if cached is not None:
        logger.debug("enricher: cache hit para %s", ioc_value)
        return cached

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
    result_map = {r.source: r for r in results}
    get_cache().set(key, result_map)
    return result_map


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
