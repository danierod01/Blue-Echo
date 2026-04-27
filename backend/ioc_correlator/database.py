import json
import os
from datetime import datetime, timezone
from typing import Generator, Optional

from sqlmodel import Field, Session, SQLModel, create_engine, select


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------

class ScanResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    ioc_value: str = Field(index=True)
    ioc_type: str                        # "ipv4" | "ipv6" | "md5" | ... (IOCType.value)

    score: int = Field(default=0)        # 0-100
    verdict: str = Field(default="")    # "clean" | "suspicious" | "malicious" | "critical"

    # Resultados por conector serializados como JSON
    connector_results: str = Field(default="{}")

    ai_summary: str = Field(default="")

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
) -> ScanResult:
    scan = ScanResult(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        score=score,
        verdict=verdict,
        connector_results=json.dumps(connector_results, ensure_ascii=False),
        ai_summary=ai_summary,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def get_history(session: Session, limit: int = 50) -> list[ScanResult]:
    stmt = (
        select(ScanResult)
        .order_by(ScanResult.created_at.desc(), ScanResult.id.desc())
        .limit(limit)
    )
    return list(session.exec(stmt).all())


def get_scan_by_id(session: Session, scan_id: int) -> Optional[ScanResult]:
    return session.get(ScanResult, scan_id)
