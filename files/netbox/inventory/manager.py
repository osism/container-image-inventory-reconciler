# SPDX-License-Identifier: Apache-2.0

"""Main inventory manager that coordinates all inventory operations."""

from typing import Any, Dict, List

from loguru import logger

from config import Config
from utils import get_inventory_hostname
from .data_cache import DataCache
from .file_writer import FileWriter
from .host_group_writer import HostGroupWriter


class InventoryManager:
    """Manages inventory file operations."""

    def __init__(self, config: Config, api=None, netbox_client=None, file_cache=None):
        self.config = config
        self.data_cache = DataCache(
            config, api=api, netbox_client=netbox_client, file_cache=file_cache
        )
        self.file_writer = FileWriter(config)
        self.host_group_writer = HostGroupWriter(config)

    def extract_device_data(self, device: Any, data_types: List[str] = None) -> None:
        """Extract various device data types and cache them.

        Args:
            device: The NetBox device object
            data_types: List of data types to extract.
                       If None, only config_context and primary_ip will be used.
        """
        self.data_cache.extract_and_cache(device, data_types)

    def extract_device_config_context(self, device: Any) -> None:
        """Extract only config context and cache it."""
        self.extract_device_data(device, data_types=["config_context"])

    def write_device_data(self, device: Any, data_types: List[str] = None) -> None:
        """Write various device data types to appropriate files.

        Args:
            device: The NetBox device object
            data_types: List of data types to extract and write.
                       If None, only config_context and primary_ip will be used.
        """
        if data_types is None:
            data_types = ["config_context", "primary_ip"]

        # Get cached data if available, otherwise extract it
        device_name = get_inventory_hostname(device)
        all_data = self.data_cache.get_cached_data(device)

        if all_data:
            logger.debug(f"Using cached data for device {device_name}")
        else:
            # Extract if not cached
            all_data = self.data_cache.extract_and_cache(device, data_types)

        # Check if we should skip writing (multiple matches case)
        if not self._should_write_device_data(device):
            return

        # Write each data type to its own file
        for data_type in data_types:
            if data_type not in all_data:
                logger.warning(f"Unknown data type '{data_type}' for device {device}")
                continue

            data = all_data[data_type]
            self.file_writer.write_device_data(device, data_type, data)

    def write_device_config_context(self, device: Any) -> None:
        """Legacy method for backward compatibility - writes only config context."""
        self.write_device_data(device, data_types=["config_context"])

    def write_host_groups(self, devices_to_roles: Dict[str, List[Any]]) -> None:
        """Write host groups to inventory file based on device roles.

        Args:
            devices_to_roles: Dictionary mapping role slugs to lists of devices
        """
        self.host_group_writer.write_host_groups(devices_to_roles)

    def _should_write_device_data(self, device: Any) -> bool:
        """Check if device data should be written.

        Args:
            device: The NetBox device object

        Returns:
            True if data should be written, False otherwise
        """
        host_vars_path = self.config.inventory_path / "host_vars"
        device_hostname = get_inventory_hostname(device)
        device_pattern = f"{device_hostname}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {device_hostname}, skipping data writing"
            )
            return False

        return True
