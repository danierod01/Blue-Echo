import logging
from datetime import datetime, timezone

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.securitytrails.com/v1"


class SecurityTrailsConnector(BaseConnector):
    name = "securitytrails"
    supported_types = [IOCType.DOMAIN, IOCType.IPV4]
    api_key_env = "SECURITYTRAILS_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        headers = {"APIKEY": self.api_key, "Accept": "application/json"}
        async with self._make_client() as client:
            if ioc_type == IOCType.DOMAIN:
                resp = await client.get(f"{_BASE_URL}/domain/{ioc_value}", headers=headers)
            else:
                resp = await client.get(f"{_BASE_URL}/ips/nearby/{ioc_value}", headers=headers)
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value, ioc_type)

    def _parse(self, body: dict, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        try:
            if ioc_type == IOCType.DOMAIN:
                return self._parse_domain(body, ioc_value)
            return self._parse_ip(body, ioc_value)
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            logger.warning("securitytrails: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="SecurityTrails: respuesta inesperada de la API.",
                error="parse_error",
            )

    def _parse_domain(self, body: dict, ioc_value: str) -> ConnectorResult:
        whois: dict = body.get("whois", {}) or {}
        created_date: str = whois.get("createdDate", "") or ""
        registrar: str = whois.get("registrar", {}).get("name", "") if isinstance(whois.get("registrar"), dict) else ""
        alexa: int = body.get("alexa_rank") or 0
        subdomains_count: int = body.get("subdomain_count") or 0

        days_old: int | None = None
        if created_date:
            try:
                dt = datetime.fromisoformat(created_date.replace("Z", "+00:00"))
                days_old = (datetime.now(timezone.utc) - dt).days
            except ValueError:
                pass

        # Dominio recién registrado es sospechoso
        if days_old is not None and days_old < 30:
            verdict = "suspicious"
            age_str = f"registrado hace {days_old} días (NUEVO)"
        elif days_old is not None:
            verdict = "clean"
            age_str = f"registrado hace {days_old} días"
        else:
            verdict = "clean"
            age_str = "fecha de registro desconocida"

        parts = [age_str]
        if registrar:
            parts.append(f"registrar: {registrar}")
        if alexa:
            parts.append(f"Alexa rank: #{alexa}")
        if subdomains_count:
            parts.append(f"{subdomains_count} subdominios")

        return ConnectorResult(
            source=self.name,
            success=True,
            verdict=verdict,
            summary=f"SecurityTrails: {', '.join(parts)}.",
            data={
                "days_old": days_old,
                "registrar": registrar,
                "alexa_rank": alexa,
                "subdomain_count": subdomains_count,
            },
        )

    def _parse_ip(self, body: dict, ioc_value: str) -> ConnectorResult:
        blocks: list = body.get("blocks", []) or []
        hostnames = [h for block in blocks for h in (block.get("hostnames") or [])]

        return ConnectorResult(
            source=self.name,
            success=True,
            verdict="clean",
            summary=f"SecurityTrails: {len(hostnames)} hostnames en el bloque /24.",
            data={"nearby_hostnames": hostnames[:20], "hostname_count": len(hostnames)},
        )
