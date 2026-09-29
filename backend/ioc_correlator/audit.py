"""Log de auditoría de eventos relevantes para seguridad.

Emite líneas estructuradas por el logger `blueecho.audit` (capturadas por
`docker compose logs`). Registra quién hace qué: escaneos, invitaciones,
revocaciones e intentos de acceso fallidos. Ayuda a la trazabilidad y al
no-repudio (STRIDE: Repudiation), sin guardar el token completo.
"""

import logging

logger = logging.getLogger("blueecho.audit")


def mask_token(token: str | None) -> str:
    """Enmascara un token para el log: nunca se escribe entero."""
    if not token:
        return "-"
    return token[:8] + "…"


def audit(event: str, **fields) -> None:
    """Registra un evento de auditoría con campos clave=valor."""
    parts = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
    logger.info("AUDIT event=%s %s", event, parts)
