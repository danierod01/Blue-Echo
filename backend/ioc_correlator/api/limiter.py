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


limiter = Limiter(key_func=_get_real_ip)
