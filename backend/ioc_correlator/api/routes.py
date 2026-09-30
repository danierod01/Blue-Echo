import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from sqlmodel import Session

from ioc_correlator.api.auth import require_api_key
from ioc_correlator.api.limiter import limiter
from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.api.schemas import (
    ConnectorResultOut,
    GeoLocation,
    HealthResponse,
    HistoryItem,
    HistoryPage,
    MitreTechnique,
    PivotEntity,
    ExtractedObject,
    PcapIocItem,
    PcapScanResponse,
    PcapTrafficStats,
    ScanRequest,
    ScanResponse,
    SourceStatus,
    TriageUpdate,
)
from ioc_correlator.ai_analyst import generate_pcap_summary, generate_summary
from ioc_correlator.geolocator import geolocate
from ioc_correlator.pcap_analyzer import analyze_pcap, is_pcap
from ioc_correlator.database import (
    get_history, get_scan_by_id, get_session, save_scan,
    WatchedIoc,
    add_watched_ioc, list_watched_iocs, remove_watched_ioc, record_watch_check,
    list_watch_alerts, ack_watch_alert,
    get_stats,
    update_scan_triage, parse_tags, TRIAGE_STATES,
)
from ioc_correlator.alerting import maybe_send_alert
from ioc_correlator.audit import audit, mask_token
from ioc_correlator.mitre_mapper import map_to_mitre
from ioc_correlator.pivots import extract_pivots
from ioc_correlator.report_pdf import build_scan_pdf
from ioc_correlator.siem_export import to_misp, to_stix
from ioc_correlator.celery_app import celery_app
from ioc_correlator.tasks import scan_ioc_task
from celery.result import AsyncResult
from ioc_correlator.enricher import enrich, get_sources_status
from ioc_correlator.extractor import extract_iocs_from_bytes
from ioc_correlator.scorer import compute_score
from ioc_correlator.utils.validators import IOCType, detect_ioc_type, is_valid_ioc

logger = logging.getLogger(__name__)
router = APIRouter()
APP_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_scan_response(db_scan, breakdown: dict[str, int], geolocation=None) -> ScanResponse:
    raw_results: dict = json.loads(db_scan.connector_results)
    connector_out = {
        name: ConnectorResultOut(**data)
        for name, data in raw_results.items()
    }
    mitre = [
        MitreTechnique(**vars(t))
        for t in map_to_mitre(raw_results)
    ]
    geo_out = None
    if geolocation is not None:
        geo_out = GeoLocation(
            lat=geolocation.lat,
            lon=geolocation.lon,
            city=geolocation.city,
            region=geolocation.region,
            country=geolocation.country,
            country_code=geolocation.country_code,
            org=geolocation.org,
            resolved_ip=geolocation.resolved_ip,
        )

    pivots = [
        PivotEntity(**p)
        for p in extract_pivots(
            raw_results,
            db_scan.ioc_value,
            db_scan.ioc_type,
            resolved_ip=geo_out.resolved_ip if geo_out else None,
        )
    ]

    return ScanResponse(
        id=db_scan.id,
        ioc_value=db_scan.ioc_value,
        ioc_type=db_scan.ioc_type,
        score=db_scan.score,
        verdict=db_scan.verdict,
        breakdown=breakdown,
        connector_results=connector_out,
        ai_summary=db_scan.ai_summary,
        created_at=db_scan.created_at,
        mitre_techniques=mitre,
        geolocation=geo_out,
        pivots=pivots,
        triage=getattr(db_scan, "triage", "new"),
        note=getattr(db_scan, "note", ""),
        tags=parse_tags(getattr(db_scan, "tags", "[]")),
    )


async def _run_scan(
    ioc_value: str,
    session: Session,
    api_key: str = "",
) -> tuple:
    """Núcleo del escaneo: enrich → score → save. Devuelve (db_scan, breakdown)."""
    ioc_value = ioc_value.strip()
    ioc_type: IOCType = detect_ioc_type(ioc_value)

    if ioc_type == IOCType.UNKNOWN:
        raise HTTPException(
            status_code=422,
            detail=f"No se reconoce el tipo de IOC: '{ioc_value}'.",
        )

    connector_results = await enrich(ioc_value, ioc_type)
    scoring = compute_score(connector_results)
    ai_summary = await generate_summary(ioc_value, ioc_type.value, scoring, connector_results)

    serializable = {
        name: {
            "source": r.source,
            "success": r.success,
            "verdict": r.verdict,
            "summary": r.summary,
            "data": r.data,
            "error": r.error,
        }
        for name, r in connector_results.items()
    }

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

    await maybe_send_alert(ioc_value, ioc_type.value, scoring.score, scoring.verdict)

    audit(
        "scan",
        ioc=ioc_value,
        type=ioc_type.value,
        score=scoring.score,
        verdict=scoring.verdict,
        token=mask_token(api_key),
    )

    return db_scan, scoring.breakdown


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=APP_VERSION)


@router.post("/scan", response_model=ScanResponse)
@limiter.limit(os.getenv("RATE_LIMIT_SCAN", "10/minute"))
async def scan(
    request: Request,
    ioc: Optional[str] = Form(default=None),
    file: Optional[UploadFile] = File(default=None),
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> ScanResponse:
    if file is not None:
        content = await file.read()
        max_bytes = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10")) * 1024 * 1024
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Fichero demasiado grande. Máximo permitido: {max_bytes // (1024 * 1024)} MB.",
            )
        if is_pcap(content):
            raise HTTPException(
                status_code=422,
                detail="Fichero PCAP detectado. Usa el endpoint /api/scan/pcap para analizar capturas de red.",
            )
        extracted = extract_iocs_from_bytes(content)
        if not extracted:
            raise HTTPException(
                status_code=422,
                detail="No se encontraron IOCs válidos en el fichero.",
            )
        # Escanea el primer IOC extraído. Multi-IOC se implementa en el frontend.
        ioc_value = extracted[0].value
    elif ioc:
        if len(ioc) > 2048:
            raise HTTPException(status_code=422, detail="El campo 'ioc' es demasiado largo (máx. 2048 caracteres).")
        ioc_value = ioc
    else:
        raise HTTPException(
            status_code=422,
            detail="Proporciona un IOC en el campo 'ioc' o sube un fichero de logs.",
        )

    db_scan, breakdown = await _run_scan(ioc_value, session, current_key)
    geo = await geolocate(ioc_value, db_scan.ioc_type)
    return _build_scan_response(db_scan, breakdown, geolocation=geo)


@router.post("/scan/json", response_model=ScanResponse)
@limiter.limit(os.getenv("RATE_LIMIT_SCAN", "10/minute"))
async def scan_json(
    request: Request,
    body: ScanRequest,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> ScanResponse:
    """Variante que acepta JSON puro (útil para peticiones desde código)."""
    db_scan, breakdown = await _run_scan(body.ioc, session, current_key)
    geo = await geolocate(body.ioc, db_scan.ioc_type)
    return _build_scan_response(db_scan, breakdown, geolocation=geo)


@router.post("/scan/pcap", response_model=PcapScanResponse)
@limiter.limit(os.getenv("RATE_LIMIT_SCAN", "10/minute"))
async def scan_pcap(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> PcapScanResponse:
    """Analiza un fichero PCAP/PCAPNG con IA y extrae IOCs del tráfico de red."""
    content = await file.read()
    max_bytes = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10")) * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Fichero demasiado grande. Máximo permitido: {max_bytes // (1024 * 1024)} MB.",
        )
    if not is_pcap(content):
        raise HTTPException(
            status_code=422,
            detail="El fichero no es un PCAP o PCAPNG válido.",
        )

    try:
        iocs, stats, extracted_objects = await analyze_pcap(content)
    except Exception as exc:
        logger.error("scan_pcap: error al analizar — %s", exc)
        raise HTTPException(status_code=500, detail=f"Error al analizar el PCAP: {exc}")

    filename = file.filename or "capture.pcap"
    ai_summary = await generate_pcap_summary(filename, stats)

    iocs_serialized = [
        {"value": ioc.value, "ioc_type": ioc.ioc_type.value} for ioc in iocs
    ]
    save_scan(
        session,
        ioc_value=filename,
        ioc_type="pcap",
        score=0,
        verdict="pcap",
        api_key=current_key or None,
        connector_results={
            "pcap_analyzer": {
                "source": "pcap_analyzer",
                "success": True,
                "verdict": "info",
                "summary": f"{len(iocs)} IOCs extraídos de {stats.get('total_packets', 0)} paquetes",
                "data": {
                    "total_packets": stats.get("total_packets", 0),
                    "total_bytes": stats.get("total_bytes", 0),
                    "protocols": stats.get("protocols", {}),
                    "ioc_count": len(iocs),
                },
                "error": None,
            },
            "__pcap_data__": {
                "iocs_found": iocs_serialized,
                "stats": stats,
                "extracted_objects": extracted_objects,
            },
        },
        ai_summary=ai_summary,
    )

    return PcapScanResponse(
        filename=filename,
        ai_summary=ai_summary,
        iocs_found=[
            PcapIocItem(value=ioc.value, ioc_type=ioc.ioc_type.value)
            for ioc in iocs
        ],
        total_iocs=len(iocs),
        stats=PcapTrafficStats(**stats),
        extracted_objects=[ExtractedObject(**obj) for obj in extracted_objects],
    )


@router.get("/history", response_model=HistoryPage)
@limiter.limit("30/minute")
async def history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    ioc_type: Optional[str] = None,
    verdict: Optional[str] = None,
    search: Optional[str] = None,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> HistoryPage:
    ioc_types = [t.strip() for t in ioc_type.split(",")] if ioc_type else None
    scans, total = get_history(
        session,
        limit=limit,
        offset=offset,
        ioc_types=ioc_types,
        verdict=verdict,
        search=search.strip() if search else None,
        api_key=current_key or None,
    )
    return HistoryPage(
        items=[
            HistoryItem(
                id=s.id,
                ioc_value=s.ioc_value,
                ioc_type=s.ioc_type,
                score=s.score,
                verdict=s.verdict,
                created_at=s.created_at,
                triage=s.triage,
                tags=parse_tags(s.tags),
            )
            for s in scans
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/history/{scan_id}/pcap", response_model=PcapScanResponse)
@limiter.limit("30/minute")
async def history_pcap_detail(
    request: Request,
    scan_id: int,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> PcapScanResponse:
    db_scan = get_scan_by_id(session, scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    if current_key and db_scan.api_key and db_scan.api_key != current_key:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    if db_scan.ioc_type != "pcap":
        raise HTTPException(status_code=422, detail="Este escaneo no es un PCAP.")

    raw = json.loads(db_scan.connector_results)
    pcap_data = raw.get("__pcap_data__", {})

    return PcapScanResponse(
        filename=db_scan.ioc_value,
        ai_summary=db_scan.ai_summary,
        iocs_found=[PcapIocItem(**ioc) for ioc in pcap_data.get("iocs_found", [])],
        total_iocs=len(pcap_data.get("iocs_found", [])),
        stats=PcapTrafficStats(**pcap_data["stats"]) if pcap_data.get("stats") else PcapTrafficStats(
            total_packets=0, total_bytes=0, unique_src_ips=[], unique_dst_ips=[],
            top_connections=[], dns_queries=[], http_hosts=[], tls_sni=[], protocols={},
        ),
        extracted_objects=[ExtractedObject(**obj) for obj in pcap_data.get("extracted_objects", [])],
    )


@router.get("/history/{scan_id}", response_model=ScanResponse)
@limiter.limit("30/minute")
async def history_detail(
    request: Request,
    scan_id: int,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> ScanResponse:
    db_scan = get_scan_by_id(session, scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    if current_key and db_scan.api_key and db_scan.api_key != current_key:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    raw = json.loads(db_scan.connector_results)
    connector_objs = {name: ConnectorResult(**d) for name, d in raw.items()}
    scoring = compute_score(connector_objs)
    geo = await geolocate(db_scan.ioc_value, db_scan.ioc_type)
    return _build_scan_response(db_scan, scoring.breakdown, geolocation=geo)


@router.get("/history/{scan_id}/pdf", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def history_detail_pdf(
    request: Request,
    scan_id: int,
    session: Session = Depends(get_session),
) -> Response:
    """Descarga el informe del escaneo en PDF (roadmap F4)."""
    db_scan = get_scan_by_id(session, scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")

    raw = json.loads(db_scan.connector_results)
    connector_objs = {name: ConnectorResult(**d) for name, d in raw.items()}
    scoring = compute_score(connector_objs)
    geo = await geolocate(db_scan.ioc_value, db_scan.ioc_type)
    scan = _build_scan_response(db_scan, scoring.breakdown, geolocation=geo)

    pdf_bytes = build_scan_pdf(scan)
    filename = f"blue-echo-scan-{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scan/async")
@limiter.limit("30/minute")
async def scan_async(
    request: Request,
    body: ScanRequest,
    current_key: str = Depends(require_api_key),
) -> dict:
    """Encola un escaneo en segundo plano (roadmap R3, Celery+Redis).

    Devuelve un `task_id` con el que consultar el estado en `/api/tasks/{id}`.
    Útil para no bloquear la petición en escaneos largos o de muchas fuentes.
    """
    task = scan_ioc_task.delay(body.ioc, current_key or None)
    return {"task_id": task.id, "status": "queued"}


@router.get("/tasks/{task_id}")
@limiter.limit("60/minute")
async def task_status(
    request: Request,
    task_id: str,
    _: str = Depends(require_api_key),
) -> dict:
    """Consulta el estado/resultado de una tarea de escaneo en segundo plano."""
    res = AsyncResult(task_id, app=celery_app)
    out: dict = {"task_id": task_id, "status": res.status}
    if res.successful():
        out["result"] = res.result
    elif res.failed():
        out["error"] = str(res.result)
    return out


@router.patch("/history/{scan_id}/triage", response_model=ScanResponse)
@limiter.limit("60/minute")
async def update_triage(
    request: Request,
    scan_id: int,
    body: TriageUpdate,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> ScanResponse:
    """Actualiza el triaje del analista (estado/nota/etiquetas) de un escaneo (A-lite)."""
    if body.triage is not None and body.triage not in TRIAGE_STATES:
        raise HTTPException(status_code=422, detail=f"Estado de triaje inválido: {body.triage}")
    db_scan = update_scan_triage(
        session, scan_id, api_key=current_key or None,
        triage=body.triage, note=body.note, tags=body.tags,
    )
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    raw = json.loads(db_scan.connector_results)
    connector_objs = {name: ConnectorResult(**d) for name, d in raw.items()}
    scoring = compute_score(connector_objs)
    return _build_scan_response(db_scan, scoring.breakdown)


@router.get("/history/{scan_id}/export")
@limiter.limit("20/minute")
async def history_detail_export(
    request: Request,
    scan_id: int,
    format: str = Query("stix", pattern="^(stix|misp)$"),
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> Response:
    """Exporta el escaneo a un formato SIEM/TI estándar (roadmap I2).

    `format=stix`  → bundle STIX 2.1
    `format=misp`  → evento MISP JSON
    """
    db_scan = get_scan_by_id(session, scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    # Mismo aislamiento por token que el resto del historial.
    if current_key and db_scan.api_key and db_scan.api_key != current_key:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")

    raw = json.loads(db_scan.connector_results)
    connector_objs = {name: ConnectorResult(**d) for name, d in raw.items()}
    scoring = compute_score(connector_objs)
    scan = _build_scan_response(db_scan, scoring.breakdown)

    if format == "misp":
        payload = to_misp(scan)
        filename = f"blue-echo-scan-{scan_id}-misp.json"
    else:
        payload = to_stix(scan)
        filename = f"blue-echo-scan-{scan_id}-stix.json"

    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Watchlist — monitorización continua (SOC-B)
# ---------------------------------------------------------------------------

def _watched_out(w) -> dict:
    return {
        "id": w.id, "ioc_value": w.ioc_value, "ioc_type": w.ioc_type, "note": w.note,
        "last_score": w.last_score, "last_verdict": w.last_verdict,
        "last_checked_at": w.last_checked_at, "created_at": w.created_at,
    }


def _alert_out(a) -> dict:
    return {
        "id": a.id, "ioc_value": a.ioc_value, "ioc_type": a.ioc_type,
        "old_verdict": a.old_verdict, "new_verdict": a.new_verdict,
        "old_score": a.old_score, "new_score": a.new_score,
        "acknowledged": a.acknowledged, "created_at": a.created_at,
    }


@router.post("/watchlist")
@limiter.limit("30/minute")
async def watchlist_add(
    request: Request,
    body: ScanRequest,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> dict:
    """Añade un IOC a la watchlist para monitorización continua."""
    ioc = body.ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == IOCType.UNKNOWN:
        raise HTTPException(status_code=422, detail=f"No se reconoce el tipo de IOC: '{ioc}'.")
    w = add_watched_ioc(session, ioc_value=ioc, ioc_type=ioc_type.value, api_key=current_key or None)
    return _watched_out(w)


@router.get("/watchlist")
@limiter.limit("60/minute")
async def watchlist_list(
    request: Request,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> list[dict]:
    """Lista los IOCs monitorizados del usuario."""
    return [_watched_out(w) for w in list_watched_iocs(session, api_key=current_key or None)]


@router.get("/watchlist/alerts")
@limiter.limit("60/minute")
async def watchlist_alerts(
    request: Request,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> list[dict]:
    """Alertas de cambio de veredicto (sin reconocer primero)."""
    return [_alert_out(a) for a in list_watch_alerts(session, api_key=current_key or None)]


@router.post("/watchlist/alerts/{alert_id}/ack")
@limiter.limit("60/minute")
async def watchlist_ack_alert(
    request: Request,
    alert_id: int,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> dict:
    """Marca una alerta como reconocida."""
    if not ack_watch_alert(session, alert_id, api_key=current_key or None):
        raise HTTPException(status_code=404, detail="Alerta no encontrada.")
    return {"acknowledged": alert_id}


@router.post("/watchlist/{watched_id}/check")
@limiter.limit("20/minute")
async def watchlist_check_now(
    request: Request,
    watched_id: int,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> dict:
    """Re-escanea ahora un IOC monitorizado (enrich + score, sin IA) y registra
    el resultado; si el veredicto cambió, genera la alerta."""
    w = session.get(WatchedIoc, watched_id)
    if w is None or (current_key and w.api_key and w.api_key != current_key):
        raise HTTPException(status_code=404, detail="IOC monitorizado no encontrado.")
    ioc_type = detect_ioc_type(w.ioc_value)
    results = await enrich(w.ioc_value, ioc_type)
    scoring = compute_score(results)
    alert = record_watch_check(session, w, score=scoring.score, verdict=scoring.verdict)
    out = _watched_out(w)
    out["alert"] = _alert_out(alert) if alert else None
    return out


@router.delete("/watchlist/{watched_id}")
@limiter.limit("30/minute")
async def watchlist_remove(
    request: Request,
    watched_id: int,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> dict:
    """Elimina un IOC de la watchlist."""
    if not remove_watched_ioc(session, watched_id, api_key=current_key or None):
        raise HTTPException(status_code=404, detail="IOC monitorizado no encontrado.")
    return {"removed": watched_id}


@router.get("/stats")
@limiter.limit("60/minute")
async def stats(
    request: Request,
    session: Session = Depends(get_session),
    current_key: str = Depends(require_api_key),
) -> dict:
    """Métricas agregadas del historial del usuario para el dashboard SOC (SOC-D)."""
    return get_stats(session, api_key=current_key or None)


@router.get("/sources", response_model=list[SourceStatus], dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def sources(request: Request) -> list[SourceStatus]:
    return [SourceStatus(**s) for s in get_sources_status()]
