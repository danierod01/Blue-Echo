"""Tests del sistema de invitaciones y del aislamiento de historial por token
(feature de la rama feat/invite-tokens).

Cubre:
- POST /api/auth/invite: configuración, secreto, nombre obligatorio, token usable.
- GET  /api/auth/me: devuelve el nombre del token.
- POST /api/auth/verify: master key, token de BD y clave inválida.
- Aislamiento: cada token solo ve SUS escaneos; el detalle de un escaneo ajeno
  devuelve 404 (no revela existencia).
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from datetime import datetime, timedelta, timezone  # noqa: E402

from main import app  # noqa: E402
from ioc_correlator.connectors.base import ConnectorResult  # noqa: E402
from ioc_correlator.database import (  # noqa: E402
    get_session,
    create_api_key,
    is_valid_api_key,
)

_VT_OK = ConnectorResult(
    source="virustotal", success=True,
    data={"malicious": 23, "suspicious": 0, "total": 87, "stats": {}},
    verdict="malicious", summary="VT",
)


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session, monkeypatch):
    # enrich mockeado para que el escaneo no llame a APIs externas
    async def fake_enrich(ioc_value, ioc_type):
        return {"virustotal": _VT_OK}

    monkeypatch.setattr("ioc_correlator.api.routes.enrich", fake_enrich)
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/auth/invite
# ---------------------------------------------------------------------------

def test_invite_returns_503_when_not_configured(client, monkeypatch):
    monkeypatch.delenv("ADMIN_SECRET", raising=False)
    r = client.post("/api/auth/invite", json={"admin_secret": "x", "label": "Ana"})
    assert r.status_code == 503


def test_invite_wrong_secret_returns_403(client, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    r = client.post("/api/auth/invite", json={"admin_secret": "malo", "label": "Ana"})
    assert r.status_code == 403


def test_invite_requires_label(client, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    r = client.post("/api/auth/invite", json={"admin_secret": "s3cr3t", "label": "   "})
    assert r.status_code == 422


def test_invite_success_returns_usable_token(client, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")  # activa la auth
    r = client.post("/api/auth/invite", json={"admin_secret": "s3cr3t", "label": "Ana"})
    assert r.status_code == 200
    token = r.json()["token"]
    assert token and r.json()["label"] == "Ana"
    # El token recién creado debe ser válido para acceder a rutas protegidas
    me = client.get("/api/auth/me", headers={"X-API-Key": token})
    assert me.status_code == 200
    assert me.json()["name"] == "Ana"


# ---------------------------------------------------------------------------
# GET /api/auth/me
# ---------------------------------------------------------------------------

def test_me_with_master_key_is_administrador(client, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    r = client.get("/api/auth/me", headers={"X-API-Key": "master"})
    assert r.status_code == 200
    assert r.json()["name"] == "Administrador"  # la master no tiene label en BD


def test_me_without_key_is_401(client, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    r = client.get("/api/auth/me")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/auth/verify
# ---------------------------------------------------------------------------

def test_verify_accepts_master_and_db_token_rejects_garbage(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="tok-valido", label="Bob")

    assert client.post("/api/auth/verify", json={"api_key": "master"}).json()["valid"] is True
    assert client.post("/api/auth/verify", json={"api_key": "tok-valido"}).json()["valid"] is True
    assert client.post("/api/auth/verify", json={"api_key": "no-existe"}).json()["valid"] is False


# ---------------------------------------------------------------------------
# Aislamiento de historial por token
# ---------------------------------------------------------------------------

def test_history_is_isolated_per_token(client, session, monkeypatch):
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    create_api_key(session, key="tokenA", label="Ana")
    create_api_key(session, key="tokenB", label="Bob")

    # Ana escanea una IP, Bob otra
    ra = client.post("/api/scan/json", json={"ioc": "1.1.1.1"}, headers={"X-API-Key": "tokenA"})
    rb = client.post("/api/scan/json", json={"ioc": "2.2.2.2"}, headers={"X-API-Key": "tokenB"})
    assert ra.status_code == 200 and rb.status_code == 200
    id_a = ra.json()["id"]

    # El historial de cada uno solo contiene lo suyo
    hist_a = client.get("/api/history", headers={"X-API-Key": "tokenA"}).json()
    values_a = [h["ioc_value"] for h in hist_a["items"]]
    assert values_a == ["1.1.1.1"]

    hist_b = client.get("/api/history", headers={"X-API-Key": "tokenB"}).json()
    values_b = [h["ioc_value"] for h in hist_b["items"]]
    assert values_b == ["2.2.2.2"]

    # Bob NO puede ver el detalle del escaneo de Ana → 404 (no 403, no revela existencia)
    detail = client.get(f"/api/history/{id_a}", headers={"X-API-Key": "tokenB"})
    assert detail.status_code == 404

    # Ana sí ve el suyo
    own = client.get(f"/api/history/{id_a}", headers={"X-API-Key": "tokenA"})
    assert own.status_code == 200
    assert own.json()["ioc_value"] == "1.1.1.1"


# ---------------------------------------------------------------------------
# Caducidad de tokens
# ---------------------------------------------------------------------------

def test_expired_token_is_invalid(session):
    past = datetime.now(timezone.utc) - timedelta(days=1)
    create_api_key(session, key="tok-caducado", label="Viejo", expires_at=past)
    assert is_valid_api_key(session, "tok-caducado") is False


def test_future_token_is_valid(session):
    future = datetime.now(timezone.utc) + timedelta(days=7)
    create_api_key(session, key="tok-vigente", label="Nuevo", expires_at=future)
    assert is_valid_api_key(session, "tok-vigente") is True


def test_invite_negative_expiry_is_422(client, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    r = client.post("/api/auth/invite",
                    json={"admin_secret": "s3cr3t", "label": "Ana", "expires_in_days": -3})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Listado y revocación de tokens
# ---------------------------------------------------------------------------

def test_list_tokens_requires_admin_secret(client, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    r = client.post("/api/auth/tokens", json={"admin_secret": "malo"})
    assert r.status_code == 403


def test_list_tokens_returns_masked_keys(client, session, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    create_api_key(session, key="supersecreto-token-1234", label="Ana")
    r = client.post("/api/auth/tokens", json={"admin_secret": "s3cr3t"})
    assert r.status_code == 200
    tokens = r.json()
    assert any(t["label"] == "Ana" for t in tokens)
    # nunca se devuelve el token completo
    for t in tokens:
        assert "supersecreto-token-1234" not in t["key_preview"]
        assert t["key_preview"].endswith("…")


def test_revoke_token_makes_it_invalid(client, session, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    monkeypatch.setenv("BLUE_ECHO_API_KEY", "master")
    obj = create_api_key(session, key="tok-a-revocar", label="Temporal")

    # Antes de revocar: el token da acceso
    assert client.get("/api/auth/me", headers={"X-API-Key": "tok-a-revocar"}).status_code == 200

    # Revocar
    r = client.post("/api/auth/revoke", json={"admin_secret": "s3cr3t", "token_id": obj.id})
    assert r.status_code == 200

    # Después de revocar: el token deja de valer -> 401
    assert client.get("/api/auth/me", headers={"X-API-Key": "tok-a-revocar"}).status_code == 401


def test_revoke_unknown_token_is_404(client, monkeypatch):
    monkeypatch.setenv("ADMIN_SECRET", "s3cr3t")
    r = client.post("/api/auth/revoke", json={"admin_secret": "s3cr3t", "token_id": 99999})
    assert r.status_code == 404
