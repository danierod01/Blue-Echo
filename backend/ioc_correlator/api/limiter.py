import hashlib
import os

from slowapi import Limiter
from starlette.requests import Request

_scan_limit = os.getenv("RATE_LIMIT_SCAN", "10/minute")
_default_limit = os.getenv("RATE_LIMIT_DEFAULT", "60/minute")


def _get_real_ip(request: Request) -> str:
    """Devuelve la IP real del cliente aunque haya un proxy nginx delante.

    Nginx propaga X-Real-IP desde $remote_addr (no es falsificable por el cliente
    porque proxy_set_header sobreescribe cualquier header que enviase el cliente).
    En desarrollo directo (sin proxy) se usa request.client.host como fallback.
    """
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"


def _rate_key(request: Request) -> str:
    """Clave de rate limiting: por **token** si viene autenticado, si no por IP.

    Así un token no comparte cupo con toda una red detrás de NAT, y un abuso se
    puede acotar al token concreto. Se prefija para no colisionar IP con token.
    """
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        # No exponemos el token en claves/logs: usamos un hash corto estable.
        digest = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        return f"key:{digest}"
    return f"ip:{_get_real_ip(request)}"


limiter = Limiter(key_func=_rate_key)
