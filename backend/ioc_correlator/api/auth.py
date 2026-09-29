import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from sqlmodel import Session

from ioc_correlator.api.limiter import limiter
from ioc_correlator.database import (
    create_api_key,
    get_api_key_label,
    get_session,
    is_valid_api_key,
    list_api_keys,
    revoke_api_key,
)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

auth_router = APIRouter()


class VerifyRequest(BaseModel):
    api_key: str


class VerifyResponse(BaseModel):
    valid: bool


class InviteRequest(BaseModel):
    admin_secret: str
    label: str = ""
    expires_in_days: Optional[int] = None  # None = no caduca


class InviteResponse(BaseModel):
    token: str
    label: str


class MeResponse(BaseModel):
    name: str


class AdminRequest(BaseModel):
    admin_secret: str


class RevokeRequest(BaseModel):
    admin_secret: str
    token_id: int


class TokenInfo(BaseModel):
    id: int
    label: str
    key_preview: str          # solo un prefijo, nunca el token completo
    active: bool
    created_at: datetime
    expires_at: Optional[datetime]


def _require_admin(admin_secret: str) -> None:
    """Valida el ADMIN_SECRET para operaciones de administración de tokens."""
    expected = os.getenv("ADMIN_SECRET", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Sistema de invitaciones no configurado.")
    if not hmac.compare_digest(admin_secret.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Código de acceso incorrecto.")


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
    _require_admin(body.admin_secret)

    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=422, detail="El nombre es obligatorio.")

    expires_at = None
    if body.expires_in_days is not None:
        if body.expires_in_days <= 0:
            raise HTTPException(status_code=422, detail="La caducidad debe ser un número de días positivo.")
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    token = secrets.token_urlsafe(32)
    create_api_key(session, key=token, label=label, expires_at=expires_at)
    return InviteResponse(token=token, label=label)


@auth_router.post("/auth/tokens", response_model=list[TokenInfo])
@limiter.limit("30/minute")
async def list_tokens(
    request: Request,
    body: AdminRequest,
    session: Session = Depends(get_session),
) -> list[TokenInfo]:
    """Lista los tokens emitidos (solo un prefijo de cada uno). Requiere ADMIN_SECRET."""
    _require_admin(body.admin_secret)
    return [
        TokenInfo(
            id=k.id,
            label=k.label,
            key_preview=k.key[:8] + "…",
            active=k.active,
            created_at=k.created_at,
            expires_at=k.expires_at,
        )
        for k in list_api_keys(session)
    ]


@auth_router.post("/auth/revoke")
@limiter.limit("30/minute")
async def revoke(
    request: Request,
    body: RevokeRequest,
    session: Session = Depends(get_session),
) -> dict:
    """Revoca (desactiva) un token por su id. Requiere ADMIN_SECRET."""
    _require_admin(body.admin_secret)
    if not revoke_api_key(session, body.token_id):
        raise HTTPException(status_code=404, detail="Token no encontrado.")
    return {"revoked": body.token_id}


async def require_api_key(
    api_key: str = Security(_api_key_header),
    session: Session = Depends(get_session),
) -> str:
    """Valida la API key y la devuelve para que los endpoints puedan filtrar por usuario."""
    key = api_key or ""
    if not _check_key(key, session):
        raise HTTPException(status_code=401, detail="API key inválida o ausente.")
    return key


@auth_router.get("/auth/me", response_model=MeResponse)
async def me(
    current_key: str = Depends(require_api_key),
    session: Session = Depends(get_session),
) -> MeResponse:
    """Devuelve el nombre asociado al token actual (para mostrarlo en la UI)."""
    label = get_api_key_label(session, current_key) if current_key else None
    return MeResponse(name=label or "Administrador")
