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
from ioc_correlator.audit import audit, mask_token
from ioc_correlator.database import (
    create_api_key,
    get_api_key_label,
    get_api_key_role,
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
    admin_secret: str = ""     # opcional si se autentica con un token admin en la cabecera
    label: str = ""
    expires_in_days: Optional[int] = None  # None = no caduca
    role: str = "analyst"      # "admin" | "analyst"


class InviteResponse(BaseModel):
    token: str
    label: str
    role: str


class MeResponse(BaseModel):
    name: str
    role: str


class AdminRequest(BaseModel):
    admin_secret: str = ""


class RevokeRequest(BaseModel):
    admin_secret: str = ""
    token_id: int


class TokenInfo(BaseModel):
    id: int
    label: str
    role: str
    key_preview: str          # solo un prefijo, nunca el token completo
    active: bool
    created_at: datetime
    expires_at: Optional[datetime]


def _is_admin_key(key: str, session: Session) -> bool:
    """True si la key es la master key (BLUE_ECHO_API_KEY) o un token con rol admin."""
    if not key:
        return False
    master = os.getenv("BLUE_ECHO_API_KEY", "").strip()
    if master and hmac.compare_digest(key.encode(), master.encode()):
        return True
    return get_api_key_role(session, key) == "admin"


def _require_admin_access(admin_secret: str, request: Request, session: Session) -> None:
    """Autoriza operaciones de administración de tokens por cualquiera de estas vías:

    1. Un token con rol **admin** (o la master key) en la cabecera `X-API-Key`.
    2. El `ADMIN_SECRET` del servidor en el cuerpo (bootstrap: para crear el
       primer token admin cuando aún no existe ninguno).
    """
    header_key = request.headers.get("X-API-Key", "")
    if _is_admin_key(header_key, session):
        return

    expected = os.getenv("ADMIN_SECRET", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Sistema de administración no configurado.")
    if admin_secret and hmac.compare_digest(admin_secret.encode(), expected.encode()):
        return
    audit("admin_auth_failed")
    raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador.")


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
    """Genera un token de acceso. Requiere privilegios de administrador
    (ADMIN_SECRET o un token admin en la cabecera)."""
    _require_admin_access(body.admin_secret, request, session)

    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=422, detail="El nombre es obligatorio.")

    role = body.role.strip().lower()
    if role not in ("admin", "analyst"):
        raise HTTPException(status_code=422, detail="Rol inválido (admin | analyst).")

    expires_at = None
    if body.expires_in_days is not None:
        if body.expires_in_days <= 0:
            raise HTTPException(status_code=422, detail="La caducidad debe ser un número de días positivo.")
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    token = secrets.token_urlsafe(32)
    create_api_key(session, key=token, label=label, expires_at=expires_at, role=role)
    audit("invite_created", label=label, role=role, token=mask_token(token))
    return InviteResponse(token=token, label=label, role=role)


@auth_router.post("/auth/tokens", response_model=list[TokenInfo])
@limiter.limit("30/minute")
async def list_tokens(
    request: Request,
    body: AdminRequest,
    session: Session = Depends(get_session),
) -> list[TokenInfo]:
    """Lista los tokens emitidos (solo un prefijo de cada uno). Requiere admin."""
    _require_admin_access(body.admin_secret, request, session)
    return [
        TokenInfo(
            id=k.id,
            label=k.label,
            role=k.role,
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
    """Revoca (desactiva) un token por su id. Requiere admin."""
    _require_admin_access(body.admin_secret, request, session)
    if not revoke_api_key(session, body.token_id):
        raise HTTPException(status_code=404, detail="Token no encontrado.")
    audit("token_revoked", token_id=body.token_id)
    return {"revoked": body.token_id}


async def require_api_key(
    api_key: str = Security(_api_key_header),
    session: Session = Depends(get_session),
) -> str:
    """Valida la API key y la devuelve para que los endpoints puedan filtrar por usuario."""
    key = api_key or ""
    if not _check_key(key, session):
        audit("auth_failed", token=mask_token(key) if key else "-")
        raise HTTPException(status_code=401, detail="API key inválida o ausente.")
    return key


@auth_router.get("/auth/me", response_model=MeResponse)
async def me(
    current_key: str = Depends(require_api_key),
    session: Session = Depends(get_session),
) -> MeResponse:
    """Devuelve el nombre y el rol del token actual (para mostrarlo en la UI)."""
    label = get_api_key_label(session, current_key) if current_key else None
    # Sin auth (dev) o master key → admin; si no, el rol del token en BD.
    if not current_key or _is_admin_key(current_key, session):
        role = "admin"
    else:
        role = get_api_key_role(session, current_key) or "analyst"
    return MeResponse(name=label or "Administrador", role=role)
