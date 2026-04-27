import base64
import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalConnector(BaseConnector):
    name = "virustotal"
    supported_types = [
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.DOMAIN,
        IOCType.URL,
    ]
    api_key_env = "VT_API_KEY"

    def _endpoint(self, ioc_value: str, ioc_type: IOCType) -> str:
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return f"{_BASE_URL}/ip_addresses/{ioc_value}"
        if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"{_BASE_URL}/files/{ioc_value}"
        if ioc_type == IOCType.DOMAIN:
            return f"{_BASE_URL}/domains/{ioc_value}"
        # URL: VT usa el base64url del string (sin padding) como identificador
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
        return f"{_BASE_URL}/urls/{url_id}"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        endpoint = self._endpoint(ioc_value, ioc_type)
        async with self._make_client() as client:
            resp = await client.get(
                endpoint,
                headers={"x-apikey": self.api_key},
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body: dict, ioc_value: str) -> ConnectorResult:
        try:
            attrs = body["data"]["attributes"]
            stats: dict = attrs.get("last_analysis_stats", {})
            malicious: int = stats.get("malicious", 0)
            suspicious: int = stats.get("suspicious", 0)
            total: int = sum(stats.values()) if stats else 0

            if malicious > 5:
                verdict = "malicious"
            elif malicious > 0 or suspicious > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return ConnectorResult(
                source=self.name,
                success=True,
                data={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                    "stats": stats,
                },
                verdict=verdict,
                summary=(
                    f"VirusTotal: {malicious}/{total} motores lo detectan como malicioso."
                ),
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("virustotal: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="VirusTotal: respuesta inesperada de la API.",
                error="parse_error",
            )
