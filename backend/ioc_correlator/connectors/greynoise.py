import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.greynoise.io/v3/community"


class GreyNoiseConnector(BaseConnector):
    name = "greynoise"
    supported_types = [IOCType.IPV4]
    api_key_env = "GREYNOISE_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/{ioc_value}",
                headers={"key": self.api_key},
            )
            # 404 = IP not observed by GreyNoise → clean, not an error
            if resp.status_code == 404:
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    data={"seen": False, "classification": "unknown", "noise": False},
                    verdict="clean",
                    summary="GreyNoise: IP no observada en internet ruidoso.",
                )
            resp.raise_for_status()
            return self._parse(resp.json())

    def _parse(self, body: dict) -> ConnectorResult:
        try:
            seen: bool = body.get("seen", False)
            classification: str = body.get("classification", "unknown")
            noise: bool = body.get("noise", False)
            name: str = body.get("name", "")

            verdict_map = {
                "malicious": "malicious",
                "benign":    "clean",
                "unknown":   "clean",
            }
            verdict = verdict_map.get(classification, "clean")

            if not seen:
                summary = "GreyNoise: IP no observada en internet ruidoso."
            elif classification == "malicious":
                summary = f"GreyNoise: clasificada como MALICIOSA{f' ({name})' if name else ''}."
            elif classification == "benign":
                summary = f"GreyNoise: clasificada como benigna{f' ({name})' if name else ''}."
            else:
                summary = "GreyNoise: observada pero sin clasificación definida."

            return ConnectorResult(
                source=self.name,
                success=True,
                data={
                    "seen": seen,
                    "classification": classification,
                    "noise": noise,
                    "name": name,
                },
                verdict=verdict,
                summary=summary,
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("greynoise: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="GreyNoise: respuesta inesperada de la API.",
                error="parse_error",
            )
