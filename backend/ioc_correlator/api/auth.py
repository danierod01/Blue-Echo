import os

from fastapi import HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str = Security(_api_key_header)) -> None:
    """Dependency que valida el header X-API-Key.

    Si BLUE_ECHO_API_KEY no está configurada en el entorno, la autenticación
    se desactiva completamente para facilitar el desarrollo local.
    """
    expected = os.getenv("BLUE_ECHO_API_KEY", "").strip()
    if not expected:
        return  # Sin clave configurada, acceso libre (modo dev)
    if api_key != expected:
        raise HTTPException(status_code=401, detail="API key inválida o ausente.")
