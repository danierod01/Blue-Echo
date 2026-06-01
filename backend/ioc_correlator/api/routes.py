import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
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
    ExtractedObject,
    PcapIocItem,
    PcapScanResponse,
    PcapTrafficStats,
    ScanRequest,
    ScanResponse,
    SourceStatus,
)
from ioc_correlator.ai_analyst import generate_pcap_summary, generate_summary
from ioc_correlator.geolocator import geolocate
from ioc_correlator.pcap_analyzer import analyze_pcap, is_pcap
from ioc_correlator.database import get_history, get_scan_by_id, get_session, save_scan
from ioc_correlator.mitre_mapper import map_to_mitre
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
    )


async def _run_scan(
    ioc_value: str,
    session: Session,
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
    )

    return db_scan, scoring.breakdown


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=APP_VERSION)


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
@limiter.limit(os.getenv("RATE_LIMIT_SCAN", "10/minute"))
async def scan(
    request: Request,
    # Acepta JSON body O multipart/form-data (para subida de ficheros)
    ioc: Optional[str] = Form(default=None),
    file: Optional[UploadFile] = File(default=None),
    session: Session = Depends(get_session),
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

    db_scan, breakdown = await _run_scan(ioc_value, session)
    geo = await geolocate(ioc_value, db_scan.ioc_type)
    return _build_scan_response(db_scan, breakdown, geolocation=geo)


@router.post("/scan/json", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
@limiter.limit(os.getenv("RATE_LIMIT_SCAN", "10/minute"))
async def scan_json(
    request: Request,
    body: ScanRequest,
    session: Session = Depends(get_session),
) -> ScanResponse:
    """Variante que acepta JSON puro (útil para peticiones desde código)."""
    db_scan, breakdown = await _run_scan(body.ioc, session)
    geo = await geolocate(body.ioc, db_scan.ioc_type)
    return _build_scan_response(db_scan, breakdown, geolocation=geo)


@router.post("/scan/pcap", response_model=PcapScanResponse, dependencies=[Depends(require_api_key)])
@limiter.limit(os.getenv("RATE_LIMIT_SCAN", "10/minute"))
async def scan_pcap(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
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

    save_scan(
        session,
        ioc_value=filename,
        ioc_type="pcap",
        score=0,
        verdict="clean",
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
            }
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


@router.get("/history", response_model=HistoryPage, dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    ioc_type: Optional[str] = None,   # valores separados por coma: "ipv4,ipv6"
    verdict: Optional[str] = None,
    search: Optional[str] = None,
    session: Session = Depends(get_session),
) -> HistoryPage:
    ioc_types = [t.strip() for t in ioc_type.split(",")] if ioc_type else None
    scans, total = get_history(
        session,
        limit=limit,
        offset=offset,
        ioc_types=ioc_types,
        verdict=verdict,
        search=search.strip() if search else None,
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
            )
            for s in scans
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/history/{scan_id}", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def history_detail(
    request: Request,
    scan_id: int,
    session: Session = Depends(get_session),
) -> ScanResponse:
    db_scan = get_scan_by_id(session, scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado.")
    raw = json.loads(db_scan.connector_results)
    connector_objs = {name: ConnectorResult(**d) for name, d in raw.items()}
    scoring = compute_score(connector_objs)
    return _build_scan_response(db_scan, scoring.breakdown)


@router.get("/sources", response_model=list[SourceStatus], dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def sources(request: Request) -> list[SourceStatus]:
    return [SourceStatus(**s) for s in get_sources_status()]
