"""Alertas por webhook (roadmap F5).

Cuando un escaneo supera un umbral de score configurable, se envía una
notificación a un webhook externo (Slack, Discord, Microsoft Teams o un
endpoint genérico). El envío es *best-effort*: cualquier error se registra
pero nunca interrumpe ni rompe la respuesta del escaneo.

Configuración por variables de entorno:
    ALERT_WEBHOOK_URL       URL del webhook. Si está vacía, las alertas se
                            desactivan por completo.
    ALERT_SCORE_THRESHOLD   Score mínimo (0-100) para disparar la alerta.
                            Por defecto 70.
    ALERT_WEBHOOK_TYPE      "slack" (por defecto) | "discord" | "teams" |
                            "generic". Determina el formato del payload.
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLD = 70


def is_enabled() -> bool:
    return bool(os.getenv("ALERT_WEBHOOK_URL", "").strip())


def _threshold() -> int:
    try:
        return int(os.getenv("ALERT_SCORE_THRESHOLD", str(_DEFAULT_THRESHOLD)))
    except ValueError:
        return _DEFAULT_THRESHOLD


def _build_message(ioc_value: str, ioc_type: str, score: int, verdict: str) -> str:
    return (
        f"🚨 Blue-Echo — IOC de alto riesgo detectado\n"
        f"Indicador: {ioc_value} ({ioc_type})\n"
        f"Veredicto: {verdict.upper()} — Score {score}/100"
    )


def _build_payload(webhook_type: str, message: str,
                   ioc_value: str, ioc_type: str, score: int, verdict: str) -> dict:
    """Formatea el payload según el destino del webhook."""
    wt = webhook_type.lower()
    if wt == "discord":
        # Discord espera el texto en la clave "content".
        return {"content": message}
    if wt == "teams":
        # Tarjeta mínima compatible con los webhooks entrantes de Teams.
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "Blue-Echo: IOC de alto riesgo",
            "themeColor": "D7263D",
            "title": "🚨 Blue-Echo — IOC de alto riesgo detectado",
            "text": message.replace("\n", "  \n"),
        }
    if wt == "generic":
        # Payload estructurado para integraciones propias (SIEM, funciones, etc.).
        return {
            "source": "blue-echo",
            "event": "high_risk_ioc",
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "score": score,
            "verdict": verdict,
            "message": message,
        }
    # Slack (por defecto) y compatibles esperan la clave "text".
    return {"text": message}


async def maybe_send_alert(ioc_value: str, ioc_type: str, score: int, verdict: str) -> bool:
    """Envía una alerta si procede. Devuelve True si se envió, False si no.

    Nunca lanza excepción: los errores se registran y se devuelven como False.
    """
    if not is_enabled():
        return False
    if score < _threshold():
        return False

    url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    webhook_type = os.getenv("ALERT_WEBHOOK_TYPE", "slack")
    message = _build_message(ioc_value, ioc_type, score, verdict)
    payload = _build_payload(webhook_type, message, ioc_value, ioc_type, score, verdict)

    timeout = float(os.getenv("REQUEST_TIMEOUT", "10"))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        logger.info("Alerta enviada para %s (score %s)", ioc_value, score)
        return True
    except httpx.HTTPStatusError as exc:
        logger.warning("Webhook de alerta respondió %s", exc.response.status_code)
        return False
    except httpx.HTTPError as exc:
        logger.warning("Error enviando alerta al webhook — %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001 - nunca romper el escaneo por una alerta
        logger.error("Error inesperado enviando alerta — %s", exc)
        return False
