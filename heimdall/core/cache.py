"""
Transform Result Cache.

TTL-based in-memory cache for OSINT transform results.
Only caches successful executions; failures are never persisted so transient
network errors can be retried immediately on the next invocation.

Cache key: sha256(transform_name + entity_urn) — deterministic and collision-resistant.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

from cachetools import TTLCache

from heimdall.core.models import TransformResult

logger = logging.getLogger("heimdall.cache")

# Module-level singleton — lazily initialized from settings on first use
_cache: Optional[TTLCache] = None
_cache_enabled: bool = True


def _get_cache() -> Optional[TTLCache]:
    """Returns the shared TTLCache instance, initializing it on first call."""
    global _cache, _cache_enabled
    if _cache is None:
        try:
            from heimdall.core.config import settings

            _cache_enabled = settings.cache_enabled
            if _cache_enabled:
                _cache = TTLCache(maxsize=settings.cache_max_size, ttl=settings.cache_ttl_seconds)
                logger.info(
                    f"Transform result cache initialized: maxsize={settings.cache_max_size}, "
                    f"ttl={settings.cache_ttl_seconds}s"
                )
        except Exception as exc:
            logger.warning(f"Cache initialization failed, running without cache: {exc}")
            _cache_enabled = False
    return _cache


def _make_cache_key(transform_name: str, entity_urn: str) -> str:
    """Computes a deterministic SHA-256 cache key for a transform + entity pair."""
    raw = f"{transform_name}:{entity_urn}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def cache_get(transform_name: str, entity_urn: str) -> Optional[TransformResult]:
    """
    Retrieves a cached TransformResult for the given transform + entity combination.

    Returns ``None`` on cache miss, disabled cache, or initialization failure.
    """
    if not _cache_enabled:
        return None
    cache = _get_cache()
    if cache is None:
        return None

    key = _make_cache_key(transform_name, entity_urn)
    result: Optional[TransformResult] = cache.get(key)
    if result is not None:
        logger.debug(f"Cache HIT  [{transform_name}] {entity_urn}")
    return result


def cache_set(transform_name: str, entity_urn: str, result: TransformResult) -> None:
    """
    Stores a TransformResult in the cache.

    Only caches results with ``status == "SUCCESS"`` to prevent
    transient errors from poisoning the cache.
    """
    if not _cache_enabled or result.status != "SUCCESS":
        return

    cache = _get_cache()
    if cache is None:
        return

    key = _make_cache_key(transform_name, entity_urn)
    cache[key] = result
    logger.debug(f"Cache SET  [{transform_name}] {entity_urn} ({len(result.edges)} edges)")


def cache_clear() -> None:
    """Clears all cached entries. Useful in tests and after config reload."""
    global _cache
    if _cache is not None:
        _cache.clear()
        logger.info("Transform result cache cleared")


def cache_stats() -> dict:
    """Returns current cache usage statistics."""
    cache = _get_cache()
    if cache is None or not _cache_enabled:
        return {"enabled": False, "size": 0, "maxsize": 0}
    return {
        "enabled": True,
        "size": len(cache),
        "maxsize": cache.maxsize,
        "ttl_seconds": cache.ttl,
    }
