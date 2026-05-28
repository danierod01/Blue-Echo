import logging
from datetime import datetime, timezone

import httpx

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://rdap.org/domain"


class RDAPConnector(BaseConnector):
    name = "rdap"
    supported_types = [IOCType.DOMAIN]
    api_key_env = None  # API pública, sin autenticación

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(f"{_BASE_URL}/{ioc_value}")
            # 404 = dominio no encontrado en RDAP (TLD sin soporte o dominio no registrado)
            if resp.status_code == 404:
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    verdict="clean",
                    summary="RDAP: dominio no encontrado o TLD sin soporte RDAP.",
                    data={"found": False},
                )
            resp.raise_for_status()
            return self._parse(resp.json())

    def _parse(self, body: dict) -> ConnectorResult:
        try:
            events: list[dict] = body.get("events", [])
            dates: dict[str, str] = {
                e["eventAction"]: e["eventDate"]
                for e in events
                if "eventAction" in e and "eventDate" in e
            }

            reg_str = dates.get("registration")
            exp_str = dates.get("expiration")
            nameservers = [
                ns.get("ldhName", "")
                for ns in body.get("nameservers", [])
                if ns.get("ldhName")
            ]

            # Nombre del registrar (en entities con role "registrar")
            registrar = ""
            for entity in body.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                registrar = prop[3]
                                break
                    if registrar:
                        break

            # Calcular edad en días
            days_old: int | None = None
            if reg_str:
                try:
                    reg_date = datetime.fromisoformat(
                        reg_str.replace("Z", "+00:00")
                    )
                    days_old = (datetime.now(timezone.utc) - reg_date).days
                except ValueError:
                    pass

            if days_old is not None and days_old < 30:
                verdict = "suspicious"
                age_str = f"{days_old} días"
            else:
                verdict = "clean"
                age_str = f"{days_old} días" if days_old is not None else "desconocida"

            parts = [f"registrado hace {age_str}"]
            if registrar:
                parts.append(f"registrar: {registrar}")
            if exp_str:
                parts.append(f"expira: {exp_str[:10]}")

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict=verdict,
                summary=f"RDAP: {', '.join(parts)}.",
                data={
                    "found": True,
                    "days_old": days_old,
                    "registered": reg_str[:10] if reg_str else None,
                    "expires": exp_str[:10] if exp_str else None,
                    "registrar": registrar or None,
                    "nameservers": nameservers[:4],
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("rdap: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="RDAP: respuesta inesperada.",
                error="parse_error",
            )

    def _handle_http_error(self, exc: httpx.HTTPStatusError) -> ConnectorResult:
        if exc.response.status_code == 404:
            return ConnectorResult(
                source=self.name,
                success=True,
                verdict="clean",
                summary="RDAP: dominio no encontrado o TLD sin soporte RDAP.",
                data={"found": False},
            )
        return super()._handle_http_error(exc)
