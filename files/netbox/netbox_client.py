# SPDX-License-Identifier: Apache-2.0

"""NetBox API client implementation."""

from contextlib import contextmanager
from typing import Any, List, Optional, Tuple

from loguru import logger

from config import Config
from base import BaseNetBoxClient
from cache import CacheManager
from connection import ConnectionManager
from exceptions import NetBoxAPIError
from filters import DeviceFilter
from interfaces import InterfaceHandler


class NetBoxClient(BaseNetBoxClient):
    """Client for NetBox API operations with improved architecture."""

    def __init__(self, config: Config, file_cache=None):
        super().__init__(config)
        self._connection_manager = ConnectionManager(config)
        self._device_filter = DeviceFilter(config)
        self._cache_manager = CacheManager(ttl=600)  # 10 minute cache
        self._interface_handler: Optional[InterfaceHandler] = None
        self._file_cache = file_cache
        self._connected = False
        self.connect()

    def connect(self) -> None:
        """Establish connection to NetBox."""
        self.api = self._connection_manager.connect()
        self._interface_handler = InterfaceHandler(self.api, self._cache_manager)
        self._connected = True

    def disconnect(self) -> None:
        """Close connection to NetBox."""
        self._connection_manager.disconnect()
        self._interface_handler = None
        self._connected = False
        self.api = None
        self._cache_manager.clear()

    @contextmanager
    def api_operation(self, operation_name: str):
        """Context manager for API operations with error handling.

        Args:
            operation_name: Name of the operation for logging

        Yields:
            None

        Raises:
            NetBoxAPIError: If API operation fails
        """
        if not self._connected:
            raise NetBoxAPIError("Not connected to NetBox")

        try:
            logger.debug(f"Starting {operation_name}")
            yield
            logger.debug(f"Completed {operation_name}")
        except Exception as e:
            logger.error(f"Failed {operation_name}: {e}")
            raise NetBoxAPIError(f"Failed {operation_name}: {e}") from e

    def get_managed_devices(self) -> Tuple[List[Any], List[Any]]:
        """Retrieve managed devices from NetBox using configured filter(s).

        Returns:
            A tuple containing:
            - Devices with both base filter and managed-by-ironic tag
            - Devices with only base filter (not managed-by-ironic)

        Raises:
            NetBoxAPIError: If device retrieval fails
        """
        with self.api_operation("get_managed_devices"):
            filter_list = self._device_filter.normalize_filters()

            all_devices_with_ironic = []
            all_devices_non_ironic = []

            for base_filter in filter_list:
                # Get Ironic-managed devices
                ironic_filter = self._device_filter.build_ironic_filter(base_filter)
                devices_with_ironic = self.api.dcim.devices.filter(**ironic_filter)
                devices_with_ironic_filtered = (
                    self._device_filter.filter_by_maintenance(devices_with_ironic)
                )

                # Get non-Ironic devices
                devices_all = self.api.dcim.devices.filter(**base_filter)
                devices_non_ironic_filtered = (
                    self._device_filter.filter_non_ironic_devices(devices_all)
                )

                all_devices_with_ironic.extend(devices_with_ironic_filtered)
                all_devices_non_ironic.extend(devices_non_ironic_filtered)

            # Remove duplicates
            unique_devices_with_ironic = self._device_filter.deduplicate_devices(
                all_devices_with_ironic
            )
            unique_devices_non_ironic = self._device_filter.deduplicate_devices(
                all_devices_non_ironic
            )

            return unique_devices_with_ironic, unique_devices_non_ironic

    def get_device_oob_interface(
        self, device: Any
    ) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Get OOB management interface with IP and MAC address for a device.

        Args:
            device: NetBox device object

        Returns:
            A tuple of (ip_address, mac_address, vlan_id) or (None, None, None)
        """
        if not self._interface_handler:
            raise NetBoxAPIError("Interface handler not initialized")

        with self.api_operation(f"get_device_oob_interface for {device.name}"):
            return self._interface_handler.get_oob_interface(device)

    def get_oob_networks(self) -> List[Any]:
        """Get networks with managed-by-osism tag and OOB role.

        Returns:
            List of prefix objects that have managed-by-osism tag and OOB role
        """
        # Check cache first
        cache_key = "oob_networks"
        cached_result = self._cache_manager.get(cache_key)
        if cached_result is not None:
            return cached_result

        with self.api_operation("get_oob_networks"):
            prefixes = self.api.ipam.prefixes.filter(
                tag=["managed-by-osism"], role="oob"
            )
            result = list(prefixes)
            self._cache_manager.set(cache_key, result)
            return result

    def update_device_custom_field(
        self, device: Any, field_name: str, field_value: Any
    ) -> bool:
        """Update a custom field for a device.

        Args:
            device: NetBox device object
            field_name: Name of the custom field to update
            field_value: Value to set for the custom field

        Returns:
            True if update was successful, False otherwise
        """
        with self.api_operation(
            f"update_device_custom_field '{field_name}' for {device.name}"
        ):
            if not hasattr(device, "custom_fields"):
                device.custom_fields = {}

            device.custom_fields[field_name] = field_value
            device.save()

            # Also update file cache if enabled
            if self._file_cache:
                self._file_cache.set_custom_field(device.name, field_name, field_value)

            logger.debug(
                f"Updated custom field '{field_name}' for device {device.name}"
            )
            return True

    def __enter__(self) -> "NetBoxClient":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager and cleanup resources."""
        self.disconnect()

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self._cache_manager.clear()
        logger.info("Cache cleared")

    def invalidate_cache(self, pattern: str) -> None:
        """Invalidate cache entries matching a pattern.

        Args:
            pattern: Pattern to match cache keys
        """
        self._cache_manager.invalidate(pattern)
        logger.info(f"Cache invalidated for pattern: {pattern}")

    def get_clusters(self) -> List[Any]:
        """Get all clusters from NetBox with managed devices.

        Returns:
            List of cluster objects that have devices with managed-by-osism tag
        """
        cache_key = "clusters"
        cached_result = self._cache_manager.get(cache_key)
        if cached_result is not None:
            return cached_result

        with self.api_operation("get_clusters"):
            all_clusters = list(self.api.virtualization.clusters.all())

            # Filter clusters that have devices with managed-by-osism tag
            managed_clusters = []
            for cluster in all_clusters:
                devices = self.api.dcim.devices.filter(cluster=cluster.id)
                for device in devices:
                    if any(tag.slug == "managed-by-osism" for tag in device.tags):
                        managed_clusters.append(cluster)
                        break

            self._cache_manager.set(cache_key, managed_clusters)
            return managed_clusters

    def get_cluster_groups(self) -> List[Any]:
        """Get all cluster groups from NetBox that have managed clusters.

        Returns:
            List of cluster group objects that have clusters with managed devices
        """
        cache_key = "cluster_groups"
        cached_result = self._cache_manager.get(cache_key)
        if cached_result is not None:
            return cached_result

        with self.api_operation("get_cluster_groups"):
            all_cluster_groups = list(self.api.virtualization.cluster_groups.all())
            managed_clusters = self.get_clusters()
            managed_cluster_ids = {cluster.id for cluster in managed_clusters}

            # Filter cluster groups that have managed clusters
            managed_cluster_groups = []
            for cluster_group in all_cluster_groups:
                clusters = self.api.virtualization.clusters.filter(
                    group=cluster_group.id
                )
                for cluster in clusters:
                    if cluster.id in managed_cluster_ids:
                        managed_cluster_groups.append(cluster_group)
                        break

            self._cache_manager.set(cache_key, managed_cluster_groups)
            return managed_cluster_groups
