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
    role: str = Field(default="analyst")                     # "admin" | "analyst"
    active: bool = Field(default=True)                       # revocación
    expires_at: Optional[datetime] = Field(default=None)    # caducidad (None = no caduca)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InviteCode(SQLModel, table=True):
    """Código de invitación de un solo uso. El admin lo genera y lo reparte; la
    persona lo canjea en /invite (con su nombre) para crear su propio token."""
    id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(index=True, unique=True)
    role: str = Field(default="analyst")                  # rol que concede el token canjeado
    label: str = Field(default="")                        # nota del admin (para quién/para qué)
    active: bool = Field(default=True)                     # revocación por el admin
    used: bool = Field(default=False)                      # de un solo uso
    used_by: str = Field(default="")                       # nombre con el que se canjeó
    used_at: Optional[datetime] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)  # caducidad opcional (None = no caduca)
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

    # Triaje del analista (A-lite): estado + nota + etiquetas (JSON list)
    triage: str = Field(default="new")     # new|investigating|confirmed|false_positive|resolved
    note: str = Field(default="")
    tags: str = Field(default="[]")        # JSON: lista de strings

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Estados de triaje válidos (A-lite).
TRIAGE_STATES = ("new", "investigating", "confirmed", "false_positive", "resolved")


class WatchedIoc(SQLModel, table=True):
    """IOC bajo monitorización continua (roadmap SOC-B). Se re-escanea de forma
    periódica y se genera una alerta cuando su veredicto cambia."""
    id: Optional[int] = Field(default=None, primary_key=True)
    ioc_value: str = Field(index=True)
    ioc_type: str
    note: str = Field(default="")

    last_score: Optional[int] = Field(default=None)
    last_verdict: Optional[str] = Field(default=None)
    last_checked_at: Optional[datetime] = Field(default=None)

    active: bool = Field(default=True)
    api_key: Optional[str] = Field(default=None, index=True)   # dueño (aislamiento por token)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WatchAlert(SQLModel, table=True):
    """Alerta generada cuando el veredicto de un IOC monitorizado cambia."""
    id: Optional[int] = Field(default=None, primary_key=True)
    watched_ioc_id: int = Field(index=True)
    ioc_value: str
    ioc_type: str

    old_verdict: Optional[str] = Field(default=None)
    new_verdict: str = Field(default="")
    old_score: Optional[int] = Field(default=None)
    new_score: int = Field(default=0)

    acknowledged: bool = Field(default=False)
    api_key: Optional[str] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Engine y sesión
# ---------------------------------------------------------------------------

def _get_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./ioc_correlator.db")


def _make_engine():
    url = _get_database_url()
    if url.startswith("sqlite"):
        # check_same_thread solo aplica a SQLite (acceso multihilo de FastAPI).
        return create_engine(url, connect_args={"check_same_thread": False})
    # Otros backends (PostgreSQL en Docker, roadmap R2): pool_pre_ping evita
    # errores por conexiones que el servidor cerró tras un idle largo.
    return create_engine(url, pool_pre_ping=True)


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


def update_scan_triage(
    session: Session, scan_id: int, api_key: Optional[str] = None, *,
    triage: Optional[str] = None, note: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> Optional[ScanResult]:
    """Actualiza el triaje (estado/nota/etiquetas) de un escaneo. Respeta el
    aislamiento por token: devuelve None si no existe o es de otro usuario."""
    scan = session.get(ScanResult, scan_id)
    if scan is None:
        return None
    if api_key and scan.api_key and scan.api_key != api_key:
        return None
    if triage is not None:
        if triage not in TRIAGE_STATES:
            raise ValueError(f"Estado de triaje inválido: {triage}")
        scan.triage = triage
    if note is not None:
        scan.note = note
    if tags is not None:
        # Normaliza: strings no vacíos, sin duplicados, máx 10.
        clean = []
        for t in tags:
            t = str(t).strip()
            if t and t not in clean:
                clean.append(t)
        scan.tags = json.dumps(clean[:10], ensure_ascii=False)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def parse_tags(raw: str) -> list[str]:
    """Deserializa el campo tags (JSON list) de forma defensiva."""
    try:
        val = json.loads(raw or "[]")
        return [str(t) for t in val] if isinstance(val, list) else []
    except (ValueError, TypeError):
        return []


def _as_utc(dt: datetime) -> datetime:
    """Normaliza a UTC-aware (SQLite puede devolver datetimes naive)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def create_api_key(
    session: Session,
    key: str,
    label: str = "",
    expires_at: Optional[datetime] = None,
    role: str = "analyst",
) -> ApiKey:
    obj = ApiKey(key=key, label=label, expires_at=expires_at, role=role)
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


def get_api_key_role(session: Session, key: str) -> Optional[str]:
    """Devuelve el rol de un token válido (admin/analyst), o None si no existe
    o no está activo/vigente."""
    obj = session.exec(select(ApiKey).where(ApiKey.key == key)).first()
    if obj is None or not obj.active:
        return None
    if obj.expires_at is not None and _as_utc(obj.expires_at) <= datetime.now(timezone.utc):
        return None
    return obj.role


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


# ---------------------------------------------------------------------------
# Códigos de invitación (generados por el admin, canjeados en /invite)
# ---------------------------------------------------------------------------

def create_invite_code(
    session: Session,
    code: str,
    role: str = "analyst",
    label: str = "",
    expires_at: Optional[datetime] = None,
) -> InviteCode:
    obj = InviteCode(code=code, role=role, label=label, expires_at=expires_at)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def list_invite_codes(session: Session) -> list[InviteCode]:
    """Todos los códigos de invitación, más recientes primero."""
    return list(
        session.exec(select(InviteCode).order_by(InviteCode.created_at.desc())).all()
    )


def redeem_invite_code(session: Session, code: str, used_by: str) -> Optional[InviteCode]:
    """Valida y consume un código de invitación (de un solo uso).

    Devuelve el InviteCode si es válido (lo marca usado); None si no existe, está
    revocado, ya se usó o ha caducado.
    """
    obj = session.exec(select(InviteCode).where(InviteCode.code == code)).first()
    if obj is None or not obj.active or obj.used:
        return None
    if obj.expires_at is not None and _as_utc(obj.expires_at) <= datetime.now(timezone.utc):
        return None
    obj.used = True
    obj.used_by = used_by
    obj.used_at = datetime.now(timezone.utc)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def revoke_invite_code(session: Session, code_id: int) -> bool:
    """Marca un código de invitación como inactivo. False si no existe."""
    obj = session.get(InviteCode, code_id)
    if obj is None:
        return False
    obj.active = False
    session.add(obj)
    session.commit()
    return True


# ---------------------------------------------------------------------------
# Watchlist — monitorización continua (SOC-B)
# ---------------------------------------------------------------------------

def add_watched_ioc(
    session: Session, *, ioc_value: str, ioc_type: str,
    api_key: Optional[str] = None, note: str = "",
) -> WatchedIoc:
    """Añade un IOC a la watchlist del usuario (idempotente por valor+dueño)."""
    existing = session.exec(
        select(WatchedIoc).where(
            WatchedIoc.ioc_value == ioc_value,
            WatchedIoc.api_key == (api_key or None),
        )
    ).first()
    if existing:
        if not existing.active:
            existing.active = True
            session.add(existing)
            session.commit()
            session.refresh(existing)
        return existing
    obj = WatchedIoc(ioc_value=ioc_value, ioc_type=ioc_type, api_key=api_key or None, note=note)
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def list_watched_iocs(session: Session, api_key: Optional[str] = None) -> list[WatchedIoc]:
    """IOCs monitorizados del usuario (activos primero, más recientes primero)."""
    stmt = select(WatchedIoc).where(WatchedIoc.active == True)  # noqa: E712
    if api_key:
        stmt = stmt.where(WatchedIoc.api_key == api_key)
    return list(session.exec(stmt.order_by(WatchedIoc.created_at.desc())).all())


def remove_watched_ioc(session: Session, watched_id: int, api_key: Optional[str] = None) -> bool:
    """Elimina (desactiva) un IOC monitorizado. Respeta el aislamiento por token."""
    obj = session.get(WatchedIoc, watched_id)
    if obj is None:
        return False
    if api_key and obj.api_key and obj.api_key != api_key:
        return False
    obj.active = False
    session.add(obj)
    session.commit()
    return True


def iocs_due_for_check(session: Session, older_than_minutes: int) -> list[WatchedIoc]:
    """IOCs activos que no se han comprobado desde hace `older_than_minutes`."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)
    rows = session.exec(select(WatchedIoc).where(WatchedIoc.active == True)).all()  # noqa: E712
    due = []
    for r in rows:
        if r.last_checked_at is None or _as_utc(r.last_checked_at) <= cutoff:
            due.append(r)
    return due


def record_watch_check(
    session: Session, watched: WatchedIoc, *, score: int, verdict: str,
) -> Optional[WatchAlert]:
    """Actualiza el último estado de un IOC monitorizado y, si el veredicto
    cambió respecto al anterior, crea y devuelve una WatchAlert."""
    old_verdict = watched.last_verdict
    old_score = watched.last_score

    alert: Optional[WatchAlert] = None
    # Solo alerta si ya había un veredicto previo y es distinto.
    if old_verdict is not None and old_verdict != verdict:
        alert = WatchAlert(
            watched_ioc_id=watched.id, ioc_value=watched.ioc_value, ioc_type=watched.ioc_type,
            old_verdict=old_verdict, new_verdict=verdict,
            old_score=old_score, new_score=score, api_key=watched.api_key,
        )
        session.add(alert)

    watched.last_verdict = verdict
    watched.last_score = score
    watched.last_checked_at = datetime.now(timezone.utc)
    session.add(watched)
    session.commit()
    if alert:
        session.refresh(alert)
    return alert


def list_watch_alerts(session: Session, api_key: Optional[str] = None, limit: int = 50) -> list[WatchAlert]:
    """Alertas de cambio de veredicto (sin reconocer primero, más recientes primero)."""
    stmt = select(WatchAlert)
    if api_key:
        stmt = stmt.where(WatchAlert.api_key == api_key)
    stmt = stmt.order_by(WatchAlert.acknowledged.asc(), WatchAlert.created_at.desc()).limit(limit)
    return list(session.exec(stmt).all())


def ack_watch_alert(session: Session, alert_id: int, api_key: Optional[str] = None) -> bool:
    """Marca una alerta como reconocida. Respeta el aislamiento por token."""
    obj = session.get(WatchAlert, alert_id)
    if obj is None:
        return False
    if api_key and obj.api_key and obj.api_key != api_key:
        return False
    obj.acknowledged = True
    session.add(obj)
    session.commit()
    return True


# ---------------------------------------------------------------------------
# Estadísticas / analítica SOC (SOC-D)
# ---------------------------------------------------------------------------

def get_stats(session: Session, api_key: Optional[str] = None, days: int = 14, top: int = 10) -> dict:
    """Agrega métricas del historial de escaneos del usuario para el dashboard.

    Devuelve: total, distribución por veredicto y por tipo de IOC, serie temporal
    (últimos `days` días), top amenazas y un resumen de la watchlist.
    """
    from datetime import timedelta

    stmt = select(ScanResult)
    if api_key:
        stmt = stmt.where(ScanResult.api_key == api_key)
    rows = list(session.exec(stmt.order_by(col(ScanResult.created_at).desc())).all())

    verdict_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for r in rows:
        verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1
        type_counts[r.ioc_type] = type_counts.get(r.ioc_type, 0) + 1

    # Serie temporal de los últimos `days` días (rellena huecos con 0).
    today = datetime.now(timezone.utc).date()
    buckets = {(today - timedelta(days=i)): 0 for i in range(days - 1, -1, -1)}
    for r in rows:
        d = _as_utc(r.created_at).date()
        if d in buckets:
            buckets[d] += 1
    timeline = [{"date": d.isoformat(), "count": c} for d, c in buckets.items()]

    # Top amenazas: mayor score, deduplicado por IOC (se queda el más reciente).
    seen: set[str] = set()
    top_threats: list[dict] = []
    for r in sorted(rows, key=lambda x: x.score, reverse=True):
        if r.verdict not in ("malicious", "critical") or r.ioc_value in seen:
            continue
        seen.add(r.ioc_value)
        top_threats.append({
            "ioc_value": r.ioc_value, "ioc_type": r.ioc_type,
            "score": r.score, "verdict": r.verdict,
        })
        if len(top_threats) >= top:
            break

    # Resumen de la watchlist.
    wl_stmt = select(WatchedIoc).where(WatchedIoc.active == True)  # noqa: E712
    al_stmt = select(WatchAlert).where(WatchAlert.acknowledged == False)  # noqa: E712
    if api_key:
        wl_stmt = wl_stmt.where(WatchedIoc.api_key == api_key)
        al_stmt = al_stmt.where(WatchAlert.api_key == api_key)
    watched_total = len(list(session.exec(wl_stmt).all()))
    open_alerts = len(list(session.exec(al_stmt).all()))

    return {
        "total_scans": len(rows),
        "verdict_counts": verdict_counts,
        "type_counts": type_counts,
        "timeline": timeline,
        "top_threats": top_threats,
        "watchlist": {"watched": watched_total, "open_alerts": open_alerts},
    }
