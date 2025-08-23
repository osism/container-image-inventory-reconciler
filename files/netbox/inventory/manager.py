# SPDX-License-Identifier: Apache-2.0

"""Main inventory manager that coordinates all inventory operations."""

from typing import Any, Dict, List

from loguru import logger

from config import Config
from utils import get_inventory_hostname
from .data_cache import DataCache
from .file_writer import FileWriter
from .host_group_writer import HostGroupWriter
from .group_vars_writer import GroupVarsWriter


class InventoryManager:
    """Manages inventory file operations."""

    def __init__(self, config: Config, api=None, netbox_client=None, file_cache=None):
        self.config = config
        self.data_cache = DataCache(
            config, api=api, netbox_client=netbox_client, file_cache=file_cache
        )
        self.file_writer = FileWriter(config)
        self.host_group_writer = HostGroupWriter(config)
        self.group_vars_writer = GroupVarsWriter(config)

    @property
    def data_extractor(self):
        """Get the data extractor from the data cache."""
        return self.data_cache.data_extractor

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

    def write_host_groups(
        self,
        devices_to_roles: Dict[str, List[Any]],
        cluster_groups: Dict[str, List[str]] = None,
    ) -> None:
        """Write host groups to inventory file based on device roles and clusters.

        Args:
            devices_to_roles: Dictionary mapping role slugs to lists of devices
            cluster_groups: Dictionary mapping cluster/cluster group names to hosts/children
        """
        self.host_group_writer.write_host_groups(devices_to_roles, cluster_groups)

    def write_cluster_group_vars(
        self, cluster_config_contexts: Dict[str, Dict[str, Any]]
    ) -> None:
        """Write group_vars files for clusters and cluster groups with config contexts.

        Args:
            cluster_config_contexts: Dictionary mapping group names to config contexts
        """
        self.group_vars_writer.write_cluster_group_vars(cluster_config_contexts)

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

    def write_device_data_to_file(self, device: Any, data_type: str, data: Any) -> None:
        """Write specific data type directly to device file.

        Args:
            device: The NetBox device object
            data_type: Type of data being written
            data: The data to write
        """
        self.file_writer.write_device_data(device, data_type, data)
