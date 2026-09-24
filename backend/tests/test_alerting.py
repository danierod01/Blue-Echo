import httpx
import pytest

from ioc_correlator import alerting


# ---------------------------------------------------------------------------
# is_enabled / umbral
# ---------------------------------------------------------------------------

def test_disabled_without_url(monkeypatch):
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    assert alerting.is_enabled() is False


def test_enabled_with_url(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/x")
    assert alerting.is_enabled() is True


def test_threshold_default(monkeypatch):
    monkeypatch.delenv("ALERT_SCORE_THRESHOLD", raising=False)
    assert alerting._threshold() == 70


def test_threshold_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("ALERT_SCORE_THRESHOLD", "no-numero")
    assert alerting._threshold() == 70


# ---------------------------------------------------------------------------
# Formato de payload por destino
# ---------------------------------------------------------------------------

def test_payload_slack():
    p = alerting._build_payload("slack", "msg", "1.2.3.4", "ipv4", 90, "critical")
    assert p == {"text": "msg"}


def test_payload_discord():
    p = alerting._build_payload("discord", "msg", "1.2.3.4", "ipv4", 90, "critical")
    assert p == {"content": "msg"}


def test_payload_teams_is_messagecard():
    p = alerting._build_payload("teams", "msg", "1.2.3.4", "ipv4", 90, "critical")
    assert p["@type"] == "MessageCard"


def test_payload_generic_has_fields():
    p = alerting._build_payload("generic", "msg", "1.2.3.4", "ipv4", 90, "critical")
    assert p["ioc_value"] == "1.2.3.4"
    assert p["score"] == 90
    assert p["event"] == "high_risk_ioc"


# ---------------------------------------------------------------------------
# maybe_send_alert — comportamiento
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_alert_when_disabled(monkeypatch):
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    sent = await alerting.maybe_send_alert("1.2.3.4", "ipv4", 100, "critical")
    assert sent is False


@pytest.mark.asyncio
async def test_no_alert_below_threshold(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("ALERT_SCORE_THRESHOLD", "70")
    sent = await alerting.maybe_send_alert("1.2.3.4", "ipv4", 40, "suspicious")
    assert sent is False


@pytest.mark.asyncio
async def test_alert_sent_above_threshold(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("ALERT_SCORE_THRESHOLD", "70")

    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.content
        return httpx.Response(200, json={"ok": True})

    _patch_client(monkeypatch, handler)
    sent = await alerting.maybe_send_alert("185.220.101.45", "ipv4", 87, "critical")
    assert sent is True
    assert captured["url"] == "https://hooks.example.com/x"


@pytest.mark.asyncio
async def test_alert_failure_never_raises(monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("ALERT_SCORE_THRESHOLD", "70")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    _patch_client(monkeypatch, handler)
    # No debe lanzar; devuelve False al fallar el webhook.
    sent = await alerting.maybe_send_alert("1.2.3.4", "ipv4", 95, "critical")
    assert sent is False


def _patch_client(monkeypatch, handler):
    """Sustituye httpx.AsyncClient por uno con transporte mock."""
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
