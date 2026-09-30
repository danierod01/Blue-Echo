"""Tareas Celery en segundo plano (roadmap R3).

La tarea `scan_ioc_task` ejecuta el mismo pipeline que el escaneo síncrono
(enrich → score → IA → guardar en BD + alerta + auditoría), pero fuera del
ciclo petición/respuesta, en un worker independiente. Devuelve un dict
serializable en JSON (el backend de resultados de Celery es Redis).

El worker abre su propia sesión de BD (comparte la PostgreSQL del backend), por
eso R2 —Postgres— es prerrequisito de R3: con SQLite en un fichero por
contenedor, worker y API no compartirían datos.
"""

import asyncio
import logging
import os

from sqlmodel import Session

from ioc_correlator.ai_analyst import generate_summary
from ioc_correlator.alerting import maybe_send_alert
from ioc_correlator.audit import audit, mask_token
from ioc_correlator.celery_app import celery_app
from ioc_correlator.database import (
    engine,
    save_scan,
    iocs_due_for_check,
    record_watch_check,
)
from ioc_correlator.enricher import enrich
from ioc_correlator.scorer import compute_score
from ioc_correlator.utils.validators import IOCType, detect_ioc_type

logger = logging.getLogger(__name__)


async def _async_scan(ioc_value: str, api_key: str | None) -> dict:
    ioc_value = ioc_value.strip()
    ioc_type: IOCType = detect_ioc_type(ioc_value)
    if ioc_type == IOCType.UNKNOWN:
        return {"error": f"No se reconoce el tipo de IOC: '{ioc_value}'."}

    connector_results = await enrich(ioc_value, ioc_type)
    scoring = compute_score(connector_results)
    ai_summary = await generate_summary(ioc_value, ioc_type.value, scoring, connector_results)

    serializable = {
        name: {
            "source": r.source, "success": r.success, "verdict": r.verdict,
            "summary": r.summary, "data": r.data, "error": r.error,
        }
        for name, r in connector_results.items()
    }

    with Session(engine) as session:
        db_scan = save_scan(
            session,
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            score=scoring.score,
            verdict=scoring.verdict,
            connector_results=serializable,
            ai_summary=ai_summary,
            api_key=api_key or None,
        )
        scan_id = db_scan.id

    await maybe_send_alert(ioc_value, ioc_type.value, scoring.score, scoring.verdict)
    audit("scan_async", ioc=ioc_value, type=ioc_type.value,
          score=scoring.score, verdict=scoring.verdict, token=mask_token(api_key or ""))

    return {
        "id": scan_id,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type.value,
        "score": scoring.score,
        "verdict": scoring.verdict,
    }


@celery_app.task(name="scan_ioc")
def scan_ioc_task(ioc_value: str, api_key: str | None = None) -> dict:
    """Ejecuta un escaneo completo en segundo plano y devuelve un resumen."""
    return asyncio.run(_async_scan(ioc_value, api_key))


# ---------------------------------------------------------------------------
# Monitorización continua de la watchlist (SOC-B)
# ---------------------------------------------------------------------------

async def _score_ioc(ioc_value: str) -> tuple[int, str]:
    """Comprobación ligera: enrich + score, SIN IA (la monitorización no
    necesita el resumen en lenguaje natural, solo el veredicto)."""
    ioc_type: IOCType = detect_ioc_type(ioc_value)
    if ioc_type == IOCType.UNKNOWN:
        return 0, "clean"
    connector_results = await enrich(ioc_value, ioc_type)
    scoring = compute_score(connector_results)
    return scoring.score, scoring.verdict


async def _run_watchlist_checks() -> dict:
    interval = int(os.getenv("WATCHLIST_CHECK_INTERVAL_MINUTES", "60"))
    checked = 0
    alerts = 0
    with Session(engine) as session:
        due = iocs_due_for_check(session, older_than_minutes=interval)
        for watched in due:
            try:
                score, verdict = await _score_ioc(watched.ioc_value)
            except Exception as exc:  # nunca romper el ciclo por un IOC
                logger.warning("watchlist: fallo comprobando %s — %s", watched.ioc_value, exc)
                continue
            alert = record_watch_check(session, watched, score=score, verdict=verdict)
            checked += 1
            if alert is not None:
                alerts += 1
                audit("watch_alert", ioc=watched.ioc_value,
                      old=alert.old_verdict, new=alert.new_verdict)
                # Notificación best-effort (reusa el sistema de alertas por webhook;
                # solo dispara si el score supera el umbral configurado).
                await maybe_send_alert(watched.ioc_value, watched.ioc_type, score, verdict)
    return {"checked": checked, "alerts": alerts}


@celery_app.task(name="check_watchlist")
def check_watchlist_task() -> dict:
    """Re-escanea los IOCs de la watchlist vencidos y alerta si cambia el veredicto."""
    return asyncio.run(_run_watchlist_checks())
