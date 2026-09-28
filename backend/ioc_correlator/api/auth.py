import hmac
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from sqlmodel import Session

from ioc_correlator.api.limiter import limiter
from ioc_correlator.database import create_api_key, get_session, is_valid_api_key

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

auth_router = APIRouter()


class VerifyRequest(BaseModel):
    api_key: str


class VerifyResponse(BaseModel):
    valid: bool


class InviteRequest(BaseModel):
    admin_secret: str
    label: str = ""


class InviteResponse(BaseModel):
    token: str
    label: str


def _check_key(api_key: str, session: Session) -> bool:
    """Devuelve True si la key es válida (env var o BD)."""
    master = os.getenv("BLUE_ECHO_API_KEY", "").strip()
    # Sin master key configurada: acceso libre (modo dev)
    if not master:
        return True
    # Comprobar contra la master key
    if api_key and hmac.compare_digest(api_key.encode(), master.encode()):
        return True
    # Comprobar contra tokens generados en BD
    if api_key and is_valid_api_key(session, api_key):
        return True
    return False


@auth_router.post("/auth/verify", response_model=VerifyResponse)
@limiter.limit("5/minute")
async def verify(
    request: Request,
    body: VerifyRequest,
    session: Session = Depends(get_session),
) -> VerifyResponse:
    return VerifyResponse(valid=_check_key(body.api_key, session))


@auth_router.post("/auth/invite", response_model=InviteResponse)
@limiter.limit("10/hour")
async def invite(
    request: Request,
    body: InviteRequest,
    session: Session = Depends(get_session),
) -> InviteResponse:
    """Genera un token de acceso. Requiere el ADMIN_SECRET del servidor."""
    admin_secret = os.getenv("ADMIN_SECRET", "").strip()
    if not admin_secret:
        raise HTTPException(status_code=503, detail="Sistema de invitaciones no configurado.")
    if not hmac.compare_digest(body.admin_secret.encode(), admin_secret.encode()):
        raise HTTPException(status_code=403, detail="Código de acceso incorrecto.")

    token = secrets.token_urlsafe(32)
    create_api_key(session, key=token, label=body.label)
    return InviteResponse(token=token, label=body.label)


async def require_api_key(
    api_key: str = Security(_api_key_header),
    session: Session = Depends(get_session),
) -> str:
    """Valida la API key y la devuelve para que los endpoints puedan filtrar por usuario."""
    key = api_key or ""
    if not _check_key(key, session):
        raise HTTPException(status_code=401, detail="API key inválida o ausente.")
    return key
