"""
Tests for Gemini v2 service (structured output, caching, fallback).
"""
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.gemini_v2 import (
    _cache_key, _get_cached, _set_cache, call_gemini_v2,
    analyze_email_v2, get_cache_stats, _analysis_cache
)


@pytest.fixture
def mock_settings_v2():
    """Mock settings with GEMINI_USE_V2=True."""
    settings = MagicMock()
    settings.GEMINI_API_KEY = "test-gemini-key"
    settings.GEMINI_USE_V2 = True
    with patch("services.gemini_v2.get_settings", return_value=settings):
        yield settings


@pytest.fixture
def clear_cache():
    """Clear the analysis cache before each test."""
    _analysis_cache.clear()
    yield
    _analysis_cache.clear()


class TestCacheKey:
    """Tests for cache key generation."""

    def test_same_input_same_key(self):
        """Same input produces same cache key."""
        k1 = _cache_key("sender@test.com", "Hello", "Body text")
        k2 = _cache_key("sender@test.com", "Hello", "Body text")
        assert k1 == k2

    def test_different_input_different_key(self):
        """Different input produces different cache key."""
        k1 = _cache_key("sender@test.com", "Hello", "Body text")
        k2 = _cache_key("other@test.com", "Hello", "Body text")
        assert k1 != k2


class TestCache:
    """Tests for LRU cache behavior."""

    def test_cache_set_and_get(self, clear_cache):
        """Cached results can be retrieved."""
        result = {"verdict": "phishing", "confidence": 0.95}
        key = _cache_key("test", "test", "test")
        _set_cache(key, result)
        cached = _get_cached(key)
        assert cached == result

    def test_cache_miss(self, clear_cache):
        """Missing key returns None."""
        result = _get_cached("nonexistent-key")
        assert result is None

    def test_cache_eviction(self, clear_cache):
        """Cache evicts oldest entry when full."""
        # Fill cache to max
        for i in range(257):
            key = f"key-{i}"
            _set_cache(key, {"verdict": "safe"})

        assert len(_analysis_cache) <= 256


class TestAnalyzeEmailV2:
    """Tests for v2 analysis function."""

    def test_v2_no_api_key(self):
        """Returns None when no API key configured."""
        with patch("services.gemini_v2.get_settings") as mock:
            mock.return_value = MagicMock(GEMINI_API_KEY="")
            result = analyze_email_v2("test body", "sender", "subject")
            assert result is None

    def test_v2_cache_hit(self, mock_settings_v2, clear_cache):
        """Returns cached result on cache hit."""
        # Pre-populate cache
        key = _cache_key("sender@test.com", "Test", "Body")
        _set_cache(key, {"verdict": "safe", "confidence": 0.99})

        result = analyze_email_v2("Body", "sender@test.com", "Test")
        assert result is not None
        assert result["verdict"] == "safe"
        assert result["confidence"] == 0.99


class TestCacheStats:
    """Tests for cache statistics."""

    def test_cache_stats(self, clear_cache):
        """Returns correct cache statistics."""
        _set_cache("key1", {"verdict": "safe"})
        _set_cache("key2", {"verdict": "phishing"})

        stats = get_cache_stats()
        assert stats["size"] == 2
        assert stats["max_size"] == 256
        assert stats["ttl_seconds"] == 300
