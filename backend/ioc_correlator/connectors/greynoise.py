import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

# API Community de GreyNoise (tier gratuito). Devuelve una vista reducida de la
# clasificación de una IP: si es "ruido" de internet (escaneo masivo), si está
# en la lista RIOT de servicios comunes benignos, y su clasificación.
# Doc: https://docs.greynoise.io/reference/get_v3-community-ip
_BASE_URL = "https://api.greynoise.io/v3/community"


class GreyNoiseConnector(BaseConnector):
    name = "greynoise"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    api_key_env = "GREYNOISE_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/{ioc_value}",
                headers={"key": self.api_key, "Accept": "application/json"},
            )

            # 404 en la Community API NO es un error: significa que la IP no ha
            # sido observada por los sensores de GreyNoise. Se reporta como
            # "sin datos" con veredicto limpio, no como fallo del conector.
            if resp.status_code == 404:
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    data={
                        "seen": False,
                        "classification": "unknown",
                        "noise": False,
                        "riot": False,
                    },
                    verdict="clean",
                    summary="GreyNoise: IP no observada en la red de sensores.",
                )

            resp.raise_for_status()
            return self._parse(resp.json())

    def _parse(self, body: dict) -> ConnectorResult:
        try:
            classification: str = body.get("classification", "unknown")
            noise: bool = bool(body.get("noise", False))
            riot: bool = bool(body.get("riot", False))
            name: str = body.get("name", "")
            last_seen: str = body.get("last_seen", "")

            # classification puede ser "benign" | "malicious" | "unknown".
            if classification == "malicious":
                verdict = "malicious"
            elif classification == "benign":
                verdict = "clean"
            elif noise:
                # Observada escaneando internet pero sin intención confirmada.
                verdict = "suspicious"
            else:
                verdict = "clean"

            detail = f"clasificación '{classification}'"
            if name:
                detail += f" ({name})"
            if riot:
                detail += ", listada en RIOT (servicio común benigno)"
            summary = f"GreyNoise: {detail}."

            return ConnectorResult(
                source=self.name,
                success=True,
                data={
                    "seen": True,
                    "classification": classification,
                    "noise": noise,
                    "riot": riot,
                    "name": name,
                    "last_seen": last_seen,
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
