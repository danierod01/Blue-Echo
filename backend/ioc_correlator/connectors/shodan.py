import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_SENSITIVE_PORTS = {22, 3389, 445, 1433, 4444}
_BASE_URL = "https://api.shodan.io"


class ShodanConnector(BaseConnector):
    name = "shodan"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    api_key_env = "SHODAN_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/shodan/host/{ioc_value}",
                params={"key": self.api_key},
            )
            resp.raise_for_status()
            return self._parse(resp.json())

    def _parse(self, body: dict) -> ConnectorResult:
        try:
            ports: list[int] = body.get("ports", [])
            hostnames: list[str] = body.get("hostnames", [])
            country: str = body.get("country_name", "")
            org: str = body.get("org", "")
            vulns: list[str] = list(body.get("vulns", {}).keys())

            sensitive = [p for p in ports if p in _SENSITIVE_PORTS]
            verdict = "suspicious" if sensitive else "clean"

            summary = f"Shodan: {len(ports)} puertos abiertos"
            if sensitive:
                summary += f", sensibles: {sensitive}"
            if vulns:
                summary += f", {len(vulns)} CVE(s) asociados"
            summary += "."

            return ConnectorResult(
                source=self.name,
                success=True,
                data={
                    "open_ports": ports,
                    "sensitive_ports": sensitive,
                    "hostnames": hostnames,
                    "country": country,
                    "org": org,
                    "vulns": vulns,
                },
                verdict=verdict,
                summary=summary,
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("shodan: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="Shodan: respuesta inesperada de la API.",
                error="parse_error",
            )
