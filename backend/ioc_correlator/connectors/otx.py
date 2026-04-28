import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_OTX_TYPE: dict[IOCType, str] = {
    IOCType.IPV4:   "IPv4",
    IOCType.IPV6:   "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.MD5:    "file",
    IOCType.SHA1:   "file",
    IOCType.SHA256: "file",
}


class OTXConnector(BaseConnector):
    name = "otx"
    supported_types = [
        IOCType.IPV4, IOCType.IPV6,
        IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
        IOCType.DOMAIN,
    ]
    api_key_env = "OTX_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        otx_type = _OTX_TYPE[ioc_type]
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/{otx_type}/{ioc_value}/general",
                headers={"X-OTX-API-KEY": self.api_key},
            )
            resp.raise_for_status()
            return self._parse(resp.json())

    def _parse(self, body: dict) -> ConnectorResult:
        try:
            pulse_info: dict = body.get("pulse_info", {})
            pulse_count: int = pulse_info.get("count", 0)
            tags: list[str] = []
            for pulse in pulse_info.get("pulses", [])[:3]:
                tags.extend(pulse.get("tags", []))

            verdict = "malicious" if pulse_count > 0 else "clean"
            summary = (
                f"OTX: {pulse_count} pulso{'s' if pulse_count != 1 else ''} de amenaza activo{'s' if pulse_count != 1 else ''}."
            )

            return ConnectorResult(
                source=self.name,
                success=True,
                data={"pulse_count": pulse_count, "tags": list(set(tags))},
                verdict=verdict,
                summary=summary,
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("otx: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="OTX: respuesta inesperada de la API.",
                error="parse_error",
            )
