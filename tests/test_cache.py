"""
Tests for the TTL Transform Result Cache.
"""

import pytest
from heimdall.core.models import GraphEdge, TransformResult


@pytest.fixture(autouse=True)
def clear_cache_before_each():
    """Ensure each test starts with a clean cache."""
    from heimdall.core.cache import cache_clear, _cache
    cache_clear()
    yield
    cache_clear()


def _make_result(status="SUCCESS", edges=None):
    return TransformResult(
        transform_name="test_transform",
        input_entity="Domain:example.com",
        status=status,
        edges=edges or [],
        duration_ms=50.0,
    )


def _make_edge():
    return GraphEdge(
        source="Domain:example.com",
        target="IPv4:93.184.216.34",
        target_type="IPv4",
        rel="RESOLVES_TO",
        properties={},
    )


def test_cache_miss_returns_none():
    from heimdall.core.cache import cache_get
    result = cache_get("test_transform", "Domain:example.com")
    assert result is None


def test_cache_set_and_get():
    from heimdall.core.cache import cache_get, cache_set
    result = _make_result(edges=[_make_edge()])
    cache_set("test_transform", "Domain:example.com", result)
    cached = cache_get("test_transform", "Domain:example.com")
    assert cached is not None
    assert cached.status == "SUCCESS"
    assert len(cached.edges) == 1


def test_cache_does_not_store_failed():
    """Failed results must never be cached — transient errors should be retryable."""
    from heimdall.core.cache import cache_get, cache_set
    failed = _make_result(status="FAILED")
    cache_set("test_transform", "Domain:fail.com", failed)
    assert cache_get("test_transform", "Domain:fail.com") is None


def test_cache_does_not_store_skipped():
    """SKIPPED results (missing API key) should not be cached."""
    from heimdall.core.cache import cache_get, cache_set
    skipped = _make_result(status="SKIPPED")
    cache_set("test_transform", "Domain:example.com", skipped)
    assert cache_get("test_transform", "Domain:example.com") is None


def test_cache_key_is_transform_specific():
    """Same entity URN with different transforms must have separate cache slots."""
    from heimdall.core.cache import cache_get, cache_set
    r1 = _make_result()
    r2 = _make_result()
    cache_set("transform_a", "Domain:example.com", r1)
    cache_set("transform_b", "Domain:example.com", r2)
    assert cache_get("transform_a", "Domain:example.com") is not None
    assert cache_get("transform_b", "Domain:example.com") is not None


def test_cache_clear():
    from heimdall.core.cache import cache_clear, cache_get, cache_set
    result = _make_result()
    cache_set("test_transform", "Domain:example.com", result)
    cache_clear()
    assert cache_get("test_transform", "Domain:example.com") is None


def test_cache_stats_returns_dict():
    from heimdall.core.cache import cache_stats, cache_set
    result = _make_result()
    cache_set("test_transform", "Domain:example.com", result)
    stats = cache_stats()
    assert isinstance(stats, dict)
    assert "size" in stats
    assert stats["size"] >= 1
