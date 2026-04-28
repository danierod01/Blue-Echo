import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_URL_ENDPOINT  = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhausConnector(BaseConnector):
    name = "urlhaus"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    api_key_env = None  # API pública, sin autenticación

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            if ioc_type == IOCType.URL:
                resp = await client.post(_URL_ENDPOINT, data={"url": ioc_value})
            else:
                resp = await client.post(_HOST_ENDPOINT, data={"host": ioc_value})
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_type)

    def _parse(self, body: dict, ioc_type: IOCType = IOCType.URL) -> ConnectorResult:
        try:
            status: str = body.get("query_status", "no_results")

            if ioc_type == IOCType.URL:
                # Posibles valores: "is_online", "was_online", "no_results"
                found = status in ("is_online", "was_online")
                verdict_map = {
                    "is_online":  "malicious",
                    "was_online": "suspicious",
                    "no_results": "clean",
                }
                verdict = verdict_map.get(status, "unknown")
                urls_count = 1 if found else 0
            else:
                # Host endpoint: "ok" = encontrado, "no_results" = limpio
                found = status == "ok"
                urls_count = body.get("urls_count", 0) if found else 0
                verdict = "malicious" if urls_count > 0 else "clean"

            status_es = {
                "is_online":  "activa y maliciosa",
                "was_online": "fue maliciosa (inactiva)",
                "no_results": "no encontrada",
                "ok":         f"{urls_count} URL(s) maliciosas asociadas",
            }
            summary = f"URLhaus: {status_es.get(status, status)}."

            return ConnectorResult(
                source=self.name,
                success=True,
                data={"found": found, "status": status, "urls_count": urls_count},
                verdict=verdict,
                summary=summary,
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("urlhaus: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="URLhaus: respuesta inesperada de la API.",
                error="parse_error",
            )
