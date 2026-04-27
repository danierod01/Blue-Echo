from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str


class ErrorResponse(BaseModel):
    detail: str


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    ioc: str


class ConnectorResultOut(BaseModel):
    source: str
    success: bool
    verdict: str
    summary: str
    data: dict[str, Any]
    error: Optional[str] = None


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


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class SourceStatus(BaseModel):
    name: str
    available: bool
    supported_types: list[str]
