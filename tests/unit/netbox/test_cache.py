# SPDX-License-Identifier: Apache-2.0

"""Unit tests for files/netbox/cache.py.

Timestamps are driven through a patched ``time.time`` so TTL expiry is
deterministic; the tests never sleep.
"""

import pytest

from cache import CacheManager


@pytest.fixture
def clock(monkeypatch):
    """Patch ``time.time()`` with a mutable, test-controlled clock."""
    now = {"t": 1000.0}
    monkeypatch.setattr("time.time", lambda: now["t"])
    return now


class TestInit:
    def test_default_ttl_is_300(self):
        assert CacheManager().ttl == 300

    def test_custom_ttl_is_stored(self):
        assert CacheManager(ttl=60).ttl == 60


class TestGet:
    def test_hit_within_ttl_returns_value(self, clock):
        cache = CacheManager(ttl=300)
        cache.set("key", "value")
        clock["t"] += 100  # still inside the 300s window
        assert cache.get("key") == "value"

    def test_miss_returns_none(self):
        assert CacheManager().get("absent") is None

    def test_expired_entry_returns_none_and_is_evicted(self, clock):
        cache = CacheManager(ttl=300)
        cache.set("key", "value")
        clock["t"] += 400  # past the 300s TTL
        assert cache.get("key") is None
        assert "key" not in cache._cache

    def test_zero_ttl_expires_entries_immediately(self, clock):
        cache = CacheManager(ttl=0)
        cache.set("key", "value")
        # No time advance: time.time() - timestamp == 0, which is not < 0,
        # so even a same-instant lookup counts as expired.
        assert cache.get("key") is None


class TestSet:
    def test_stores_value_and_timestamp_tuple(self, clock):
        cache = CacheManager()
        cache.set("key", "value")
        assert cache._cache["key"] == ("value", 1000.0)

    def test_reset_updates_value_and_refreshes_timestamp(self, clock):
        cache = CacheManager()
        cache.set("key", "old")
        clock["t"] = 2000.0
        cache.set("key", "new")
        assert cache._cache["key"] == ("new", 2000.0)


class TestClear:
    def test_clear_empties_populated_cache(self, clock):
        cache = CacheManager()
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache._cache == {}

    def test_clear_on_empty_cache_is_noop(self):
        cache = CacheManager()
        cache.clear()
        assert cache._cache == {}


class TestInvalidate:
    def test_pattern_deletes_matching_entries_only(self, clock):
        cache = CacheManager()
        cache.set("device:1", "a")
        cache.set("device:2", "b")
        cache.set("site:1", "c")
        cache.invalidate("device")
        assert "device:1" not in cache._cache
        assert "device:2" not in cache._cache
        assert "site:1" in cache._cache  # non-matching entry retained

    def test_pattern_matching_nothing_leaves_cache_unchanged(self, clock):
        cache = CacheManager()
        cache.set("device:1", "a")
        cache.invalidate("nomatch")
        assert "device:1" in cache._cache

    def test_empty_pattern_matches_every_key(self, clock):
        # "" is a substring of every string, so invalidate("") clears all keys.
        cache = CacheManager()
        cache.set("device:1", "a")
        cache.set("site:1", "b")
        cache.invalidate("")
        assert cache._cache == {}
