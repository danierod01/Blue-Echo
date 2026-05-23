import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://ipinfo.io"


class IPinfoConnector(BaseConnector):
    name = "ipinfo"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    api_key_env = "IPINFO_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                f"{_BASE_URL}/{ioc_value}/json",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body: dict, ioc_value: str) -> ConnectorResult:
        try:
            org: str = body.get("org", "")
            country: str = body.get("country", "")
            hostname: str = body.get("hostname", "")
            city: str = body.get("city", "")

            # El campo privacy solo está disponible con add-on de pago
            privacy: dict = body.get("privacy", {})
            is_vpn: bool = privacy.get("vpn", False)
            is_proxy: bool = privacy.get("proxy", False)
            is_tor: bool = privacy.get("tor", False)
            is_hosting: bool = privacy.get("hosting", False)

            flags = [f for f, v in [("VPN", is_vpn), ("Proxy", is_proxy), ("Tor", is_tor), ("Hosting", is_hosting)] if v]

            if is_tor:
                verdict = "suspicious"
            elif is_vpn or is_proxy:
                verdict = "suspicious"
            else:
                verdict = "clean"

            parts = []
            if org:
                parts.append(f"org: {org}")
            if country:
                parts.append(f"país: {country}")
            if flags:
                parts.append(f"flags: {', '.join(flags)}")
            if hostname:
                parts.append(f"hostname: {hostname}")

            summary = "IPinfo: " + (", ".join(parts) if parts else "sin datos adicionales") + "."

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict=verdict,
                summary=summary,
                data={
                    "org": org,
                    "country": country,
                    "city": city,
                    "hostname": hostname,
                    "is_vpn": is_vpn,
                    "is_proxy": is_proxy,
                    "is_tor": is_tor,
                    "is_hosting": is_hosting,
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("ipinfo: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="IPinfo: respuesta inesperada de la API.",
                error="parse_error",
            )
