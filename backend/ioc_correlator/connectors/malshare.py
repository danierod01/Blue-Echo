import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://malshare.com/api.php"


class MalShareConnector(BaseConnector):
    name = "malshare"
    supported_types = [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]
    api_key_env = "MALSHARE_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.get(
                _BASE_URL,
                params={
                    "api_key": self.api_key,
                    "action": "details",
                    "hash": ioc_value,
                },
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body, ioc_value: str) -> ConnectorResult:
        try:
            # Respuesta de error cuando el hash no existe
            if isinstance(body, dict) and body.get("ERROR"):
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    verdict="clean",
                    summary="MalShare: hash no encontrado en la base de datos.",
                    data={"found": False},
                )

            sha256: str = body.get("SHA256", "")
            md5: str = body.get("MD5", "")
            file_type: str = body.get("F_TYPE", "")
            sources: list = body.get("SOURCES", []) or []

            summary = f"MalShare: hash encontrado en la base de datos"
            if file_type:
                summary += f", tipo: {file_type}"
            if sources:
                summary += f", {len(sources)} fuente(s)"
            summary += "."

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict="malicious",
                summary=summary,
                data={
                    "found": True,
                    "sha256": sha256,
                    "md5": md5,
                    "file_type": file_type,
                    "source_count": len(sources),
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("malshare: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="MalShare: respuesta inesperada de la API.",
                error="parse_error",
            )
