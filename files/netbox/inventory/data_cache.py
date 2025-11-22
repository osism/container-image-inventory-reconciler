# SPDX-License-Identifier: Apache-2.0

"""Data caching functionality for inventory management."""

from typing import Any, Dict, List, Optional

from loguru import logger

from bulk_loader import BulkDataLoader
from config import Config
from data_extractor import DeviceDataExtractor
from utils import get_inventory_hostname
from .base import BaseInventoryComponent


class DataCache(BaseInventoryComponent):
    """Manages caching of extracted device data."""

    def __init__(
        self,
        config: Config,
        api,
        netbox_client,
        bulk_loader: BulkDataLoader,
    ):
        super().__init__(config)
        self.data_extractor = DeviceDataExtractor(
            api=api,
            netbox_client=netbox_client,
            bulk_loader=bulk_loader,
        )
        self._cache: Dict[str, Dict[str, Any]] = {}

    def extract_and_cache(
        self, device: Any, data_types: List[str] = None
    ) -> Dict[str, Any]:
        """Extract device data and cache it.

        Args:
            device: The NetBox device object
            data_types: List of data types to extract.
                       If None, only config_context and primary_ip will be used.

        Returns:
            Dictionary containing all extracted data
        """
        if data_types is None:
            data_types = ["config_context", "primary_ip"]

        # Extract all requested data
        all_data = self.data_extractor.extract_all_data(
            device,
            self.config.default_mtu,
            self.config.default_local_as_prefix,
            self.config.frr_switch_roles,
            self.config.reconciler_mode,
        )

        # Store in cache
        device_name = get_inventory_hostname(device)
        self._cache[device_name] = all_data
        logger.debug(f"Extracted and cached data for device {device_name}")

        return all_data

    def get_cached_data(self, device: Any) -> Optional[Dict[str, Any]]:
        """Get cached data for a device.

        Args:
            device: The NetBox device object

        Returns:
            Cached data dictionary or None if not cached
        """
        device_name = get_inventory_hostname(device)
        return self._cache.get(device_name)

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        logger.debug("Cleared data cache")
