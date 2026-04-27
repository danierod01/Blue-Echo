import json

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ioc_correlator.database import (
    ScanResult,
    get_history,
    get_scan_by_id,
    save_scan,
)


# ---------------------------------------------------------------------------
# Fixture: base de datos en memoria para tests
# ---------------------------------------------------------------------------

@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_save_and_retrieve_by_id(session: Session):
    scan = save_scan(
        session,
        ioc_value="1.2.3.4",
        ioc_type="ipv4",
        score=75,
        verdict="malicious",
        connector_results={"virustotal": {"detected": True}},
        ai_summary="IP maliciosa detectada.",
    )

    assert scan.id is not None
    retrieved = get_scan_by_id(session, scan.id)
    assert retrieved is not None
    assert retrieved.ioc_value == "1.2.3.4"
    assert retrieved.score == 75
    assert retrieved.verdict == "malicious"
    assert retrieved.ai_summary == "IP maliciosa detectada."


def test_connector_results_roundtrip(session: Session):
    payload = {"virustotal": {"positives": 23, "total": 87}, "abuseipdb": {"score": 95}}
    scan = save_scan(
        session,
        ioc_value="185.220.101.45",
        ioc_type="ipv4",
        score=87,
        verdict="critical",
        connector_results=payload,
        ai_summary="",
    )

    retrieved = get_scan_by_id(session, scan.id)
    decoded = json.loads(retrieved.connector_results)
    assert decoded["virustotal"]["positives"] == 23
    assert decoded["abuseipdb"]["score"] == 95


def test_get_history_order(session: Session):
    for i in range(5):
        save_scan(
            session,
            ioc_value=f"10.0.0.{i}",
            ioc_type="ipv4",
            score=i * 10,
            verdict="clean",
            connector_results={},
            ai_summary="",
        )

    history = get_history(session, limit=10)
    # Orden descendente por id (criterio secundario garantizado cuando created_at coincide)
    ids = [h.id for h in history]
    assert ids == sorted(ids, reverse=True)


def test_get_history_limit(session: Session):
    for i in range(10):
        save_scan(
            session,
            ioc_value=f"10.0.0.{i}",
            ioc_type="ipv4",
            score=0,
            verdict="clean",
            connector_results={},
            ai_summary="",
        )

    history = get_history(session, limit=3)
    assert len(history) == 3


def test_get_scan_by_id_not_found(session: Session):
    assert get_scan_by_id(session, 9999) is None


def test_created_at_is_set(session: Session):
    scan = save_scan(
        session,
        ioc_value="example.com",
        ioc_type="domain",
        score=0,
        verdict="clean",
        connector_results={},
        ai_summary="",
    )
    assert scan.created_at is not None


def test_score_boundaries(session: Session):
    for score, verdict in [(0, "clean"), (20, "clean"), (50, "suspicious"), (100, "critical")]:
        scan = save_scan(
            session,
            ioc_value="x.com",
            ioc_type="domain",
            score=score,
            verdict=verdict,
            connector_results={},
            ai_summary="",
        )
        assert scan.score == score
