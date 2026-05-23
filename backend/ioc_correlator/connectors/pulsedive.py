import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

# AVISO: tier gratuito limitado a 10 peticiones/día
_BASE_URL = "https://pulsedive.com/api/info.php"

_RISK_VERDICT = {
    "none": "clean",
    "low": "clean",
    "medium": "suspicious",
    "high": "malicious",
    "critical": "malicious",
    "unknown": "unknown",
}


class PulsediveConnector(BaseConnector):
    name = "pulsedive"
    supported_types = [
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    ]
    api_key_env = "PULSEDIVE_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                _BASE_URL,
                params={
                    "indicator": ioc_value,
                    "key": self.api_key,
                    "pretty": 1,
                },
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body: dict, ioc_value: str) -> ConnectorResult:
        try:
            if body.get("error"):
                # "Not found" es respuesta válida, no un error de la API
                if "not found" in str(body.get("error", "")).lower():
                    return ConnectorResult(
                        source=self.name,
                        success=True,
                        verdict="clean",
                        summary="Pulsedive: IOC no encontrado en la base de datos.",
                        data={"found": False},
                    )
                return ConnectorResult(
                    source=self.name,
                    success=False,
                    verdict="unknown",
                    summary=f"Pulsedive: {body['error']}",
                    error=str(body["error"]),
                )

            risk: str = (body.get("risk") or "unknown").lower()
            indicator_type: str = body.get("type", "")
            threats: list = body.get("threats", []) or []
            threat_names = [t.get("name") for t in threats if t.get("name")]
            feeds_count: int = len(body.get("feeds", []) or [])

            verdict = _RISK_VERDICT.get(risk, "unknown")
            summary = f"Pulsedive: riesgo {risk}"
            if threat_names:
                summary += f", amenazas: {', '.join(threat_names[:3])}"
            if feeds_count:
                summary += f", presente en {feeds_count} feeds"
            summary += "."

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict=verdict,
                summary=summary,
                data={
                    "found": True,
                    "risk": risk,
                    "indicator_type": indicator_type,
                    "threats": threat_names,
                    "feeds_count": feeds_count,
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("pulsedive: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="Pulsedive: respuesta inesperada de la API.",
                error="parse_error",
            )
