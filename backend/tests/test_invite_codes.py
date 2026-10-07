"""Tests de los códigos de invitación: generación (admin), canje (público) y
revocación. Modelo: el admin genera un código y lo reparte; la persona lo canjea
en /invite con su nombre para crear su token (de un solo uso)."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from main import app  # noqa: E402
from ioc_correlator.database import (  # noqa: E402
    get_session, create_api_key, create_invite_code, redeem_invite_code, is_valid_api_key,
)


@pytest.fixture(name="session")
def _session():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture(name="client")
def _client(session):
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Capa de BD
# ---------------------------------------------------------------------------

def test_redeem_marks_single_use(session):
    create_invite_code(session, code="C1", role="analyst")
    first = redeem_invite_code(session, "C1", used_by="Ana")
    assert first is not None and first.used and first.used_by == "Ana"
    # Segundo canje → None (ya usado)
    assert redeem_invite_code(session, "C1", used_by="Bob") is None


def test_redeem_rejects_unknown_and_revoked(session):
    assert redeem_invite_code(session, "NOPE", used_by="X") is None
    c = create_invite_code(session, code="REV", role="analyst")
    c.active = False
    session.add(c); session.commit()
    assert redeem_invite_code(session, "REV", used_by="X") is None


# ---------------------------------------------------------------------------
# Endpoints admin (crear / listar / revocar) — autorizados por admin
# ---------------------------------------------------------------------------

def test_admin_creates_lists_and_revokes_code(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    hdr = {"X-API-Key": "master"}

    # Crear
    r = client.post("/api/auth/invite-codes/create", json={"label": "Para Ana", "role": "analyst"}, headers=hdr)
    assert r.status_code == 200
    code = r.json()["code"]
    code_id = r.json()["id"]
    assert r.json()["role"] == "analyst" and not r.json()["used"]

    # Listar (el admin ve el código completo para repartirlo)
    lst = client.post("/api/auth/invite-codes/list", json={}, headers=hdr)
    assert lst.status_code == 200
    assert any(c["code"] == code for c in lst.json())

    # Canje público → token analista
    red = client.post("/api/auth/invite", json={"code": code, "label": "Ana"})
    assert red.status_code == 200 and red.json()["role"] == "analyst"

    # Revocar un código
    r2 = client.post("/api/auth/invite-codes/create", json={"label": "Otro"}, headers=hdr)
    cid2 = r2.json()["id"]
    rev = client.post("/api/auth/invite-codes/revoke", json={"code_id": cid2}, headers=hdr)
    assert rev.status_code == 200
    # Un código revocado no se puede canjear
    assert client.post("/api/auth/invite", json={"code": r2.json()["code"], "label": "Z"}).status_code == 403
    # Revocar id inexistente → 404
    assert client.post("/api/auth/invite-codes/revoke", json={"code_id": 99999}, headers=hdr).status_code == 404
    assert code_id  # sanity


def test_non_admin_cannot_manage_codes(client, session, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="analyst", label="Ana", role="analyst")
    # Token analyst en cabecera y sin el ADMIN_SECRET en el cuerpo → 403.
    r = client.post("/api/auth/invite-codes/create",
                    json={"label": "X"}, headers={"X-API-Key": "analyst"})
    assert r.status_code == 403


def test_admin_code_grants_admin_token(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    r = client.post("/api/auth/invite-codes/create",
                    json={"label": "Nuevo jefe", "role": "admin"}, headers={"X-API-Key": "master"})
    code = r.json()["code"]
    red = client.post("/api/auth/invite", json={"code": code, "label": "Jefa"})
    assert red.status_code == 200 and red.json()["role"] == "admin"
    me = client.get("/api/auth/me", headers={"X-API-Key": red.json()["token"]})
    assert me.json()["role"] == "admin"
