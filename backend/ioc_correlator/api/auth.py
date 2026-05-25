import os

from fastapi import APIRouter, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

auth_router = APIRouter()


class VerifyRequest(BaseModel):
    api_key: str


class VerifyResponse(BaseModel):
    valid: bool


@auth_router.post("/auth/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest) -> VerifyResponse:
    """Endpoint público: comprueba si la API key es válida.

    El frontend lo llama en la pantalla de login. No requiere header previo.
    Si BLUE_ECHO_API_KEY no está configurada, cualquier clave es válida
    (modo desarrollo sin restricciones).
    """
    expected = os.getenv("BLUE_ECHO_API_KEY", "").strip()
    if not expected:
        return VerifyResponse(valid=True)
    return VerifyResponse(valid=body.api_key == expected)


async def require_api_key(api_key: str = Security(_api_key_header)) -> None:
    """Dependency que valida el header X-API-Key en rutas protegidas."""
    expected = os.getenv("BLUE_ECHO_API_KEY", "").strip()
    if not expected:
        return  # Sin clave configurada, acceso libre (modo dev)
    if api_key != expected:
        raise HTTPException(status_code=401, detail="API key inválida o ausente.")
