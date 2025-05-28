# SPDX-License-Identifier: Apache-2.0

"""Caching functionality for NetBox API responses."""

import time
from typing import Any, Dict, Optional, Tuple

from loguru import logger


class CacheManager:
    """Manages caching for NetBox API responses."""

    def __init__(self, ttl: int = 300):
        """Initialize cache manager.

        Args:
            ttl: Time to live for cache entries in seconds (default: 5 minutes)
        """
        self.ttl = ttl
        self._cache: Dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self.ttl:
                logger.debug(f"Cache hit for key: {key}")
                return value
            else:
                logger.debug(f"Cache expired for key: {key}")
                del self._cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        self._cache[key] = (value, time.time())
        logger.debug(f"Cached value for key: {key}")

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        logger.debug("Cache cleared")

    def invalidate(self, pattern: str) -> None:
        """Invalidate cache entries matching pattern.

        Args:
            pattern: Pattern to match cache keys (simple string matching)
        """
        keys_to_delete = [key for key in self._cache.keys() if pattern in key]
        for key in keys_to_delete:
            del self._cache[key]
        logger.debug(
            f"Invalidated {len(keys_to_delete)} cache entries matching '{pattern}'"
        )
