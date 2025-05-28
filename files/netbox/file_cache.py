# SPDX-License-Identifier: Apache-2.0

"""File-based cache persistence for NetBox custom field values."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger


class FileCache:
    """Manages persistent file-based cache for custom field values."""

    def __init__(self, cache_file: Path = None):
        """Initialize the file cache.

        Args:
            cache_file: Path to the cache file. Defaults to /tmp/netbox_cache.json
        """
        self.cache_file = cache_file or Path("/tmp/netbox_cache.json")
        self._cache: Dict[str, Dict[str, Any]] = {}

    def load(self, flush_cache: bool = False) -> Dict[str, Dict[str, Any]]:
        """Load cache from file.

        Args:
            flush_cache: If True, ignore existing cache file

        Returns:
            Loaded cache data or empty dict if flush_cache is True or file doesn't exist
        """
        if flush_cache:
            logger.info("FLUSH_CACHE is set, ignoring existing cache file")
            self._cache = {}
            return self._cache

        if not self.cache_file.exists():
            logger.debug(f"Cache file {self.cache_file} does not exist")
            self._cache = {}
            return self._cache

        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                self._cache = json.load(f)
            logger.info(
                f"Loaded cache from {self.cache_file} with {len(self._cache)} devices"
            )
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load cache file {self.cache_file}: {e}")
            self._cache = {}

        return self._cache

    def save(self) -> None:
        """Save cache to file."""
        try:
            # Ensure parent directory exists
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2, sort_keys=True)
            logger.info(
                f"Saved cache to {self.cache_file} with {len(self._cache)} devices"
            )
        except IOError as e:
            logger.error(f"Failed to save cache file {self.cache_file}: {e}")

    def get_device_cache(self, device_name: str) -> Optional[Dict[str, Any]]:
        """Get cached data for a specific device.

        Args:
            device_name: Name of the device

        Returns:
            Cached data for the device or None if not found
        """
        return self._cache.get(device_name)

    def set_device_cache(self, device_name: str, data: Dict[str, Any]) -> None:
        """Set cached data for a specific device.

        Args:
            device_name: Name of the device
            data: Data to cache
        """
        if device_name not in self._cache:
            self._cache[device_name] = {}
        self._cache[device_name].update(data)

    def get_custom_field(self, device_name: str, field_name: str) -> Optional[Any]:
        """Get a specific custom field value from cache.

        Args:
            device_name: Name of the device
            field_name: Name of the custom field

        Returns:
            Cached value or None if not found
        """
        device_data = self.get_device_cache(device_name)
        if device_data:
            return device_data.get(field_name)
        return None

    def set_custom_field(self, device_name: str, field_name: str, value: Any) -> None:
        """Set a specific custom field value in cache.

        Args:
            device_name: Name of the device
            field_name: Name of the custom field
            value: Value to cache
        """
        if device_name not in self._cache:
            self._cache[device_name] = {}
        self._cache[device_name][field_name] = value

    def clear(self) -> None:
        """Clear all cached data."""
        self._cache = {}
        logger.debug("Cleared file cache")
