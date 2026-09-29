import json
import os
from datetime import datetime, timezone
from typing import Generator, Optional

from sqlalchemy import func
from sqlmodel import Field, Session, SQLModel, col, create_engine, select


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------

class ApiKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True)
    label: str = Field(default="")
    active: bool = Field(default=True)                       # revocación
    expires_at: Optional[datetime] = Field(default=None)    # caducidad (None = no caduca)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    ioc_value: str = Field(index=True)
    ioc_type: str                        # "ipv4" | "ipv6" | "md5" | ... (IOCType.value)

    score: int = Field(default=0)        # 0-100
    verdict: str = Field(default="")    # "clean" | "suspicious" | "malicious" | "critical"

    # Resultados por conector serializados como JSON
    connector_results: str = Field(default="{}")

    ai_summary: str = Field(default="")

    # Token que creó este escaneo (None = sin auth / dev mode)
    api_key: Optional[str] = Field(default=None, index=True)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Engine y sesión
# ---------------------------------------------------------------------------

def _get_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./ioc_correlator.db")


def _make_engine():
    url = _get_database_url()
    # check_same_thread solo aplica a SQLite; no rompe otros backends
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


# El engine se crea una sola vez al importar el módulo
engine = _make_engine()


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """Dependency de FastAPI: abre sesión, hace yield, cierra al terminar."""
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# Helpers de acceso a datos
# ---------------------------------------------------------------------------

def save_scan(
    session: Session,
    *,
    ioc_value: str,
    ioc_type: str,
    score: int,
    verdict: str,
    connector_results: dict,
    ai_summary: str,
    api_key: Optional[str] = None,
) -> ScanResult:
    scan = ScanResult(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        score=score,
        verdict=verdict,
        connector_results=json.dumps(connector_results, ensure_ascii=False),
        ai_summary=ai_summary,
        api_key=api_key or None,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def get_history(
    session: Session,
    limit: int = 20,
    offset: int = 0,
    ioc_types: list[str] | None = None,
    verdict: str | None = None,
    search: str | None = None,
    api_key: str | None = None,
) -> tuple[list[ScanResult], int]:
    base = select(ScanResult)

    if api_key:
        base = base.where(ScanResult.api_key == api_key)
    if ioc_types:
        base = base.where(col(ScanResult.ioc_type).in_(ioc_types))
    if verdict:
        base = base.where(ScanResult.verdict == verdict)
    if search:
        base = base.where(col(ScanResult.ioc_value).contains(search))

    total: int = session.exec(
        select(func.count()).select_from(base.subquery())
    ).one()

    items = list(
        session.exec(
            base.order_by(ScanResult.created_at.desc(), ScanResult.id.desc())
            .offset(offset)
            .limit(limit)
        ).all()
    )
    return items, total


def get_scan_by_id(session: Session, scan_id: int) -> Optional[ScanResult]:
    return session.get(ScanResult, scan_id)


def _as_utc(dt: datetime) -> datetime:
    """Normaliza a UTC-aware (SQLite puede devolver datetimes naive)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def create_api_key(
    session: Session,
    key: str,
    label: str = "",
    expires_at: Optional[datetime] = None,
) -> ApiKey:
    obj = ApiKey(key=key, label=label, expires_at=expires_at)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def is_valid_api_key(session: Session, key: str) -> bool:
    """True solo si el token existe, está activo y no ha caducado."""
    obj = session.exec(select(ApiKey).where(ApiKey.key == key)).first()
    if obj is None or not obj.active:
        return False
    if obj.expires_at is not None and _as_utc(obj.expires_at) <= datetime.now(timezone.utc):
        return False
    return True


def get_api_key_label(session: Session, key: str) -> Optional[str]:
    """Devuelve la etiqueta (nombre) asociada a un token, o None si no existe."""
    obj = session.exec(select(ApiKey).where(ApiKey.key == key)).first()
    return obj.label if obj else None


def list_api_keys(session: Session) -> list[ApiKey]:
    """Todos los tokens (para la vista de administración), más recientes primero."""
    return list(
        session.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
    )


def revoke_api_key(session: Session, token_id: int) -> bool:
    """Marca un token como inactivo. Devuelve False si no existe."""
    obj = session.get(ApiKey, token_id)
    if obj is None:
        return False
    obj.active = False
    session.add(obj)
    session.commit()
    return True
