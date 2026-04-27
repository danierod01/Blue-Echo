import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2"
_MAX_AGE_DAYS = 90


class AbuseIPDBConnector(BaseConnector):
    name = "abuseipdb"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    api_key_env = "ABUSEIPDB_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ioc_value, "maxAgeInDays": _MAX_AGE_DAYS},
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body: dict, ioc_value: str) -> ConnectorResult:
        try:
            data = body["data"]
            confidence: int = data.get("abuseConfidenceScore", 0)
            total_reports: int = data.get("totalReports", 0)
            country: str = data.get("countryCode", "")
            isp: str = data.get("isp", "")
            last_reported: str = data.get("lastReportedAt") or "nunca"
            is_whitelisted: bool = data.get("isWhitelisted", False)

            if is_whitelisted:
                verdict = "clean"
            elif confidence > 80:
                verdict = "malicious"
            elif confidence > 50:
                verdict = "suspicious"
            elif confidence > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"

            summary = (
                f"AbuseIPDB: score de confianza {confidence}%, "
                f"{total_reports} reportes totales"
                + (f", ISP: {isp}" if isp else "")
                + (f", país: {country}" if country else "")
                + "."
            )

            return ConnectorResult(
                source=self.name,
                success=True,
                data={
                    "confidence": confidence,
                    "total_reports": total_reports,
                    "country": country,
                    "isp": isp,
                    "last_reported": last_reported,
                    "is_whitelisted": is_whitelisted,
                },
                verdict=verdict,
                summary=summary,
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("abuseipdb: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="AbuseIPDB: respuesta inesperada de la API.",
                error="parse_error",
            )
