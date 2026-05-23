import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://app.netlas.io/api"
_SENSITIVE_PORTS = {22, 23, 445, 1433, 3389, 4444, 5900, 6379, 27017}


class NetlasConnector(BaseConnector):
    name = "netlas"
    supported_types = [IOCType.IPV4, IOCType.DOMAIN]
    api_key_env = "NETLAS_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        query = f"ip:{ioc_value}" if ioc_type == IOCType.IPV4 else f"host:{ioc_value}"
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/responses/",
                headers={"X-API-Key": self.api_key},
                params={"q": query, "fields": "ip,port,protocol,host", "start": 0},
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body: dict, ioc_value: str) -> ConnectorResult:
        try:
            items: list = body.get("items", []) or []
            if not items:
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    verdict="clean",
                    summary="Netlas: sin datos de escaneo para este IOC.",
                    data={"found": False, "open_ports": []},
                )

            open_ports = list({
                item.get("data", {}).get("port")
                for item in items
                if item.get("data", {}).get("port")
            })
            sensitive = [p for p in open_ports if p in _SENSITIVE_PORTS]

            verdict = "suspicious" if sensitive else "clean"
            port_str = ", ".join(str(p) for p in sorted(open_ports[:10]))
            summary = f"Netlas: {len(open_ports)} puertos abiertos detectados ({port_str})"
            if sensitive:
                summary += f" — puertos sensibles: {', '.join(str(p) for p in sensitive)}"
            summary += "."

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict=verdict,
                summary=summary,
                data={
                    "found": True,
                    "open_ports": sorted(open_ports),
                    "sensitive_ports": sensitive,
                    "total_records": len(items),
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("netlas: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="Netlas: respuesta inesperada de la API.",
                error="parse_error",
            )
