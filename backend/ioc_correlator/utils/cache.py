import os
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TTLCache:
    """Caché en memoria con expiración por TTL.

    Thread-safe para uso con asyncio (GIL + operaciones dict atómicas).
    Las entradas expiradas se eliminan de forma lazy en el momento de la lectura.
    """

    def __init__(self, ttl: int) -> None:
        self._ttl = ttl
        self._store: dict[str, _Entry] = {}

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del self._store[key]
            return None
        return entry.value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = _Entry(
            value=value,
            expires_at=time.monotonic() + self._ttl,
        )

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        # Cuenta solo entradas no expiradas
        now = time.monotonic()
        return sum(1 for e in self._store.values() if e.expires_at > now)


def _build_cache() -> TTLCache:
    ttl = int(os.getenv("CACHE_TTL_SECONDS", 3600))
    return TTLCache(ttl=ttl)


# Instancia singleton compartida por el proceso
_cache: TTLCache = _build_cache()


def get_cache() -> TTLCache:
    return _cache


def reset_cache() -> None:
    """Usado en tests para limpiar el estado entre pruebas."""
    _cache.clear()
