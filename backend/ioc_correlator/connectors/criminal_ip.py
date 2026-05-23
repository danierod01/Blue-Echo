import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.criminalip.io/v1"

_SCORE_MAP = {"critical": "malicious", "dangerous": "malicious", "moderate": "suspicious", "low": "clean", "safe": "clean"}


class CriminalIPConnector(BaseConnector):
    name = "criminal_ip"
    supported_types = [IOCType.IPV4, IOCType.DOMAIN]
    api_key_env = "CRIMINAL_IP_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            if ioc_type == IOCType.IPV4:
                resp = await client.get(
                    f"{_BASE_URL}/ip/summary",
                    headers={"x-api-key": self.api_key},
                    params={"ip": ioc_value},
                )
            else:
                resp = await client.get(
                    f"{_BASE_URL}/domain/reports",
                    headers={"x-api-key": self.api_key},
                    params={"query": ioc_value},
                )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value, ioc_type)

    def _parse(self, body: dict, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        try:
            if ioc_type == IOCType.IPV4:
                return self._parse_ip(body, ioc_value)
            return self._parse_domain(body, ioc_value)
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("criminal_ip: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="Criminal IP: respuesta inesperada de la API.",
                error="parse_error",
            )

    def _parse_ip(self, body: dict, ioc_value: str) -> ConnectorResult:
        inbound: str = (body.get("inbound_score") or "").lower()
        outbound: str = (body.get("outbound_score") or "").lower()
        is_vpn: bool = body.get("is_vpn", False)
        is_tor: bool = body.get("is_tor", False)
        is_cloud: bool = body.get("is_cloud", False)
        country: str = body.get("country", "")

        # El score más alto entre inbound/outbound determina el veredicto
        score_priority = ["critical", "dangerous", "moderate", "low", "safe"]
        worst = next((s for s in score_priority if s in (inbound, outbound)), "safe")
        verdict = _SCORE_MAP.get(worst, "clean")

        flags = [f for f, v in [("VPN", is_vpn), ("Tor", is_tor), ("Cloud", is_cloud)] if v]
        summary = f"Criminal IP: inbound {inbound or 'n/a'}, outbound {outbound or 'n/a'}"
        if flags:
            summary += f", flags: {', '.join(flags)}"
        if country:
            summary += f", país: {country}"
        summary += "."

        return ConnectorResult(
            source=self.name,
            success=True,
            verdict=verdict,
            summary=summary,
            data={
                "inbound_score": inbound,
                "outbound_score": outbound,
                "worst_score": worst,
                "is_vpn": is_vpn,
                "is_tor": is_tor,
                "is_cloud": is_cloud,
                "country": country,
            },
        )

    def _parse_domain(self, body: dict, ioc_value: str) -> ConnectorResult:
        reports: list = body.get("data", {}).get("reports", []) or []
        if not reports:
            return ConnectorResult(
                source=self.name,
                success=True,
                verdict="clean",
                summary="Criminal IP: dominio sin reportes conocidos.",
                data={"found": False},
            )
        first = reports[0]
        score: str = (first.get("score") or "").lower()
        verdict = _SCORE_MAP.get(score, "clean")
        return ConnectorResult(
            source=self.name,
            success=True,
            verdict=verdict,
            summary=f"Criminal IP: dominio con score {score or 'desconocido'}, {len(reports)} reportes.",
            data={"found": True, "score": score, "total_reports": len(reports)},
        )
