import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import httpx

from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

# Timeout por defecto si no está en el entorno
_DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Resultado estándar devuelto por todos los conectores
# ---------------------------------------------------------------------------

@dataclass
class ConnectorResult:
    source: str                      # nombre del conector ("virustotal", "abuseipdb", …)
    success: bool                    # False si hubo error o el conector no está disponible
    data: dict = field(default_factory=dict)   # datos crudos parseados de la respuesta
    verdict: str = "unknown"         # "clean" | "suspicious" | "malicious" | "error" | "unknown"
    summary: str = ""                # una línea legible por humanos
    error: Optional[str] = None      # mensaje de error cuando success=False


# ---------------------------------------------------------------------------
# Clase base abstracta
# ---------------------------------------------------------------------------

class BaseConnector(ABC):
    """Clase base para todos los conectores de Threat Intelligence.

    Cada conector concreto debe definir:
      - name            (str)            nombre del conector
      - supported_types (list[IOCType])  tipos de IOC que sabe consultar
      - api_key_env     (str | None)     nombre de la variable de entorno con la API key
                                         None para conectores sin autenticación
    Y debe implementar:
      - _fetch(ioc_value, ioc_type)  lógica de consulta HTTP y parseo de respuesta
    """

    name: str = ""
    supported_types: list[IOCType] = []
    api_key_env: Optional[str] = None

    # ------------------------------------------------------------------
    # Consultas de estado del conector
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """True si el conector tiene API key configurada (o no la necesita)."""
        if self.api_key_env is None:
            return True
        key = os.getenv(self.api_key_env, "").strip()
        return bool(key)

    @property
    def api_key(self) -> Optional[str]:
        if self.api_key_env is None:
            return None
        return os.getenv(self.api_key_env, "").strip() or None

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    # ------------------------------------------------------------------
    # Punto de entrada público
    # ------------------------------------------------------------------

    async def query(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        """Ejecuta la consulta con manejo de errores centralizado."""
        if not self.is_available():
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary=f"{self.name}: conector no disponible (falta API key).",
                error="missing_api_key",
            )

        if not self.supports(ioc_type):
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary=f"{self.name}: no soporta el tipo {ioc_type.value}.",
                error="unsupported_ioc_type",
            )

        try:
            return await self._fetch(ioc_value, ioc_type)
        except httpx.TimeoutException:
            logger.warning("%s: timeout al consultar %s", self.name, ioc_value)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary=f"{self.name}: timeout al contactar la API.",
                error="timeout",
            )
        except httpx.HTTPStatusError as exc:
            return self._handle_http_error(exc)
        except Exception as exc:  # noqa: BLE001
            logger.error("%s: error inesperado — %s", self.name, exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary=f"{self.name}: error interno.",
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Método que cada conector concreto implementa
    # ------------------------------------------------------------------

    @abstractmethod
    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        """Realiza la petición HTTP y transforma la respuesta en ConnectorResult."""

    # ------------------------------------------------------------------
    # Helpers reutilizables por los conectores
    # ------------------------------------------------------------------

    def _make_client(self) -> httpx.AsyncClient:
        timeout = float(os.getenv("REQUEST_TIMEOUT", _DEFAULT_TIMEOUT))
        return httpx.AsyncClient(timeout=timeout)

    def _handle_http_error(self, exc: httpx.HTTPStatusError) -> ConnectorResult:
        status = exc.response.status_code
        if status == 429:
            msg = f"{self.name}: rate limit alcanzado (429). Reintenta más tarde."
        elif status == 403:
            msg = f"{self.name}: acceso denegado (403). Verifica la API key."
        elif status == 404:
            msg = f"{self.name}: recurso no encontrado (404)."
        else:
            msg = f"{self.name}: error HTTP {status}."

        logger.warning("%s: HTTP %s al consultar la API", self.name, status)
        return ConnectorResult(
            source=self.name,
            success=False,
            verdict="unknown",
            summary=msg,
            error=f"http_{status}",
        )
