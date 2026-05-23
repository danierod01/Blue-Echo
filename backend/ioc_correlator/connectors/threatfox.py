import logging
import os

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxConnector(BaseConnector):
    name = "threatfox"
    supported_types = [
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.DOMAIN,
        IOCType.URL,
    ]
    # API pública — funciona sin key; con key se obtienen límites más altos
    api_key_env = None

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        is_hash = ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)
        payload = (
            {"query": "search_hash", "hash": ioc_value}
            if is_hash
            else {"query": "search_ioc", "search_term": ioc_value}
        )

        headers = {"Content-Type": "application/json"}
        optional_key = os.getenv("THREATFOX_API_KEY", "").strip()
        if optional_key:
            headers["Auth-Key"] = optional_key

        async with self._make_client() as client:
            resp = await client.post(_BASE_URL, json=payload, headers=headers)
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body: dict, ioc_value: str) -> ConnectorResult:
        try:
            status = body.get("query_status", "")
            if status == "no_result" or not body.get("data"):
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    verdict="clean",
                    summary="ThreatFox: IOC no encontrado en la base de datos.",
                    data={"found": False},
                )

            entries: list = body["data"]
            first = entries[0]
            malware = first.get("malware_printable") or first.get("malware", "desconocido")
            threat_type = first.get("threat_type_desc") or first.get("threat_type", "")
            confidence = first.get("confidence_level", 0)
            tags = [e.get("tags") for e in entries if e.get("tags")]
            flat_tags = [t for sublist in tags if sublist for t in sublist]

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict="malicious",
                summary=(
                    f"ThreatFox: IOC asociado a {malware}"
                    + (f" ({threat_type})" if threat_type else "")
                    + f", confianza {confidence}%."
                ),
                data={
                    "found": True,
                    "malware": malware,
                    "threat_type": threat_type,
                    "confidence": confidence,
                    "total_entries": len(entries),
                    "tags": flat_tags[:10],
                },
            )
        except (KeyError, TypeError, IndexError) as exc:
            logger.warning("threatfox: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="ThreatFox: respuesta inesperada de la API.",
                error="parse_error",
            )
