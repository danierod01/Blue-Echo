import logging
import os

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

# AVISO: tier gratuito limitado a 250 peticiones/mes
_BASE_URL = "https://search.censys.io/api/v2"
_SENSITIVE_PORTS = {22, 23, 445, 1433, 3389, 4444, 5900, 6379, 27017}


class CensysConnector(BaseConnector):
    name = "censys"
    supported_types = [IOCType.IPV4, IOCType.DOMAIN]
    # Censys usa API ID + Secret como Basic Auth — guardamos ambos en env vars separadas
    api_key_env = "CENSYS_API_ID"

    def is_available(self) -> bool:
        api_id = os.getenv("CENSYS_API_ID", "").strip()
        api_secret = os.getenv("CENSYS_API_SECRET", "").strip()
        return bool(api_id and api_secret)

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        api_id = os.getenv("CENSYS_API_ID", "").strip()
        api_secret = os.getenv("CENSYS_API_SECRET", "").strip()

        async with self._make_client() as client:
            if ioc_type == IOCType.IPV4:
                resp = await client.get(
                    f"{_BASE_URL}/hosts/{ioc_value}",
                    auth=(api_id, api_secret),
                )
            else:
                resp = await client.get(
                    f"{_BASE_URL}/hosts/search",
                    auth=(api_id, api_secret),
                    params={"q": f"dns.names:{ioc_value}", "per_page": 5},
                )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value, ioc_type)

    def _parse(self, body: dict, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        try:
            if ioc_type == IOCType.IPV4:
                return self._parse_ip(body, ioc_value)
            return self._parse_domain(body, ioc_value)
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("censys: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="Censys: respuesta inesperada de la API.",
                error="parse_error",
            )

    def _parse_ip(self, body: dict, ioc_value: str) -> ConnectorResult:
        result: dict = body.get("result", {}) or {}
        services: list = result.get("services", []) or []
        open_ports = [s.get("port") for s in services if s.get("port")]
        sensitive = [p for p in open_ports if p in _SENSITIVE_PORTS]
        asn_info: dict = result.get("autonomous_system", {}) or {}
        org: str = asn_info.get("name", "")
        country: str = result.get("location", {}).get("country_code", "")

        verdict = "suspicious" if sensitive else "clean"
        port_str = ", ".join(str(p) for p in sorted(open_ports[:8]))
        summary = f"Censys: {len(open_ports)} servicios abiertos ({port_str})"
        if org:
            summary += f", org: {org}"
        if sensitive:
            summary += f", puertos sensibles: {', '.join(str(p) for p in sensitive)}"
        summary += "."

        return ConnectorResult(
            source=self.name,
            success=True,
            verdict=verdict,
            summary=summary,
            data={
                "open_ports": sorted(open_ports),
                "sensitive_ports": sensitive,
                "org": org,
                "country": country,
            },
        )

    def _parse_domain(self, body: dict, ioc_value: str) -> ConnectorResult:
        hits: list = body.get("result", {}).get("hits", []) or []
        if not hits:
            return ConnectorResult(
                source=self.name,
                success=True,
                verdict="clean",
                summary="Censys: dominio sin resultados en el índice.",
                data={"found": False},
            )
        ips = [h.get("ip") for h in hits if h.get("ip")]
        return ConnectorResult(
            source=self.name,
            success=True,
            verdict="clean",
            summary=f"Censys: dominio asociado a {len(ips)} IP(s) indexadas.",
            data={"found": True, "associated_ips": ips[:10]},
        )
