from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    version: str


class ErrorResponse(BaseModel):
    detail: str


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    ioc: str = Field(..., min_length=1, max_length=2048)


class ConnectorResultOut(BaseModel):
    source: str
    success: bool
    verdict: str
    summary: str
    data: dict[str, Any]
    error: Optional[str] = None


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    url: str
    source: str


class ScanResponse(BaseModel):
    id: int
    ioc_value: str
    ioc_type: str
    score: int
    verdict: str
    breakdown: dict[str, int]
    connector_results: dict[str, ConnectorResultOut]
    ai_summary: str
    created_at: datetime
    mitre_techniques: list[MitreTechnique] = []


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

class HistoryItem(BaseModel):
    id: int
    ioc_value: str
    ioc_type: str
    score: int
    verdict: str
    created_at: datetime


class HistoryPage(BaseModel):
    items: list[HistoryItem]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class SourceStatus(BaseModel):
    name: str
    available: bool
    supported_types: list[str]
