import time

import pytest

from ioc_correlator.utils.cache import TTLCache, reset_cache


@pytest.fixture(autouse=True)
def clean_cache():
    reset_cache()
    yield
    reset_cache()


# ---------------------------------------------------------------------------
# TTLCache unit tests
# ---------------------------------------------------------------------------

def test_set_and_get():
    cache = TTLCache(ttl=60)
    cache.set("k", "value")
    assert cache.get("k") == "value"


def test_miss_returns_none():
    cache = TTLCache(ttl=60)
    assert cache.get("nonexistent") is None


def test_expired_entry_returns_none(monkeypatch):
    cache = TTLCache(ttl=1)
    cache.set("k", "value")
    # Adelantar el reloj más allá del TTL
    original = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: original() + 2)
    assert cache.get("k") is None


def test_expired_entry_is_removed(monkeypatch):
    cache = TTLCache(ttl=1)
    cache.set("k", "value")
    original = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: original() + 2)
    cache.get("k")  # provoca eliminación lazy
    # Restaurar reloj para que __len__ funcione
    monkeypatch.setattr(time, "monotonic", original)
    assert "k" not in cache._store


def test_overwrite_resets_ttl():
    cache = TTLCache(ttl=60)
    cache.set("k", "v1")
    cache.set("k", "v2")
    assert cache.get("k") == "v2"


def test_delete():
    cache = TTLCache(ttl=60)
    cache.set("k", "value")
    cache.delete("k")
    assert cache.get("k") is None


def test_delete_nonexistent_does_not_raise():
    cache = TTLCache(ttl=60)
    cache.delete("nonexistent")  # no debe lanzar


def test_clear():
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.clear()
    assert cache.get("a") is None
    assert cache.get("b") is None


def test_len_counts_live_entries(monkeypatch):
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    assert len(cache) == 2


def test_len_excludes_expired(monkeypatch):
    cache = TTLCache(ttl=1)
    cache.set("a", 1)
    cache.set("b", 2)
    original = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: original() + 2)
    assert len(cache) == 0


def test_stores_arbitrary_types():
    cache = TTLCache(ttl=60)
    payload = {"key": [1, 2, 3], "nested": {"x": True}}
    cache.set("complex", payload)
    assert cache.get("complex") == payload


# ---------------------------------------------------------------------------
# Integration: reset_cache clears singleton
# ---------------------------------------------------------------------------

def test_reset_cache_clears_singleton():
    from ioc_correlator.utils.cache import get_cache
    get_cache().set("test", "value")
    assert get_cache().get("test") == "value"
    reset_cache()
    assert get_cache().get("test") is None
