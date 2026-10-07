"""Tests de roles (admin/analyst), admin por cabecera y clave de rate limiting.

Refuerzo de seguridad: control de acceso basado en rol y throttling por token.
"""

import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from main import app  # noqa: E402
from ioc_correlator.database import get_session, create_api_key, get_api_key_role  # noqa: E402
from ioc_correlator.api.limiter import _rate_key  # noqa: E402


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
# Roles + administración por cabecera
# ---------------------------------------------------------------------------

def test_admin_token_can_create_invite_code_via_header(client, session, monkeypatch):
    # Sin ADMIN_SECRET configurado: un token admin en la cabecera autoriza
    # la generación de un código de invitación.
    monkeypatch.delenv("ADMIN_SECRET", raising=False)
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="adm-token", label="Jefe", role="admin")

    r = client.post("/api/auth/invite-codes/create",
                    json={"label": "Para Ana", "role": "analyst"},
                    headers={"X-API-Key": "adm-token"})
    assert r.status_code == 200
    assert r.json()["role"] == "analyst"
    code = r.json()["code"]
    # Y ese código se puede canjear para crear un token analista.
    red = client.post("/api/auth/invite", json={"code": code, "label": "Ana"})
    assert red.status_code == 200
    assert get_api_key_role(session, red.json()["token"]) == "analyst"


def test_master_key_is_admin(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    me = client.get("/api/auth/me", headers={"X-API-Key": "master"})
    assert me.status_code == 200
    assert me.json()["role"] == "admin"


def test_analyst_token_cannot_administer(client, session, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="analyst-token", label="Ana", role="analyst")

    # Analyst en cabecera y sin ADMIN_SECRET en el cuerpo → 403.
    r = client.post("/api/auth/invite-codes/create",
                    json={"label": "X", "role": "analyst"},
                    headers={"X-API-Key": "analyst-token"})
    assert r.status_code == 403


def test_me_returns_analyst_role(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="analyst-token", label="Ana", role="analyst")
    me = client.get("/api/auth/me", headers={"X-API-Key": "analyst-token"})
    assert me.status_code == 200
    assert me.json()["role"] == "analyst"
    assert me.json()["name"] == "Ana"


def test_invite_code_invalid_role_422(client, session, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    r = client.post("/api/auth/invite-codes/create",
                    json={"admin_secret": "s3cr3t", "label": "X", "role": "root"})
    assert r.status_code == 422


def test_admin_secret_still_works_as_bootstrap(client, session, monkeypatch):
    # Vía clásica (ADMIN_SECRET en el cuerpo) sigue autorizando operaciones admin.
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    r = client.post("/api/auth/invite-codes/create",
                    json={"admin_secret": "s3cr3t", "label": "Bootstrap", "role": "admin"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Rate limiting por token
# ---------------------------------------------------------------------------

def _fake_request(headers, host="10.0.0.1"):
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host))


def test_rate_key_uses_token_when_present():
    req = _fake_request({"X-API-Key": "tokenA"})
    key = _rate_key(req)
    assert key.startswith("key:")
    # Mismo token → misma clave (determinista); token distinto → clave distinta.
    assert key == _rate_key(_fake_request({"X-API-Key": "tokenA"}, host="1.2.3.4"))
    assert key != _rate_key(_fake_request({"X-API-Key": "tokenB"}))


def test_rate_key_falls_back_to_ip():
    req = _fake_request({})
    assert _rate_key(req) == "ip:10.0.0.1"
