# SPDX-License-Identifier: Apache-2.0

"""NetBox API client implementation."""

from contextlib import contextmanager
from typing import Any, List, Optional, Tuple

from loguru import logger

from config import Config
from base import BaseNetBoxClient
from cache import CacheManager
from connection import ConnectionManager
from exceptions import NetBoxAPIError, NetBoxConnectionError
from filters import DeviceFilter
from interfaces import InterfaceHandler


class NetBoxClient(BaseNetBoxClient):
    """Client for NetBox API operations with improved architecture."""

    def __init__(self, config: Config):
        super().__init__(config)
        self._connection_manager = ConnectionManager(config)
        self._device_filter = DeviceFilter(config)
        self._cache_manager = CacheManager(ttl=600)  # 10 minute cache
        self._interface_handler: Optional[InterfaceHandler] = None
        self._connected = False
        self.connect()

    def connect(self) -> None:
        """Establish connection to NetBox."""
        self.api = self._connection_manager.connect()
        self._interface_handler = InterfaceHandler(self.api, self._cache_manager)
        self._connected = True

    def verify_connectivity(self) -> bool:
        """Verify that NetBox is reachable and API is usable.

        Performs a comprehensive check by attempting to access the devices endpoint
        to validate both connectivity and API token permissions.

        Returns:
            bool: True if connectivity check passes

        Raises:
            NetBoxConnectionError: If NetBox is not reachable or API access fails
        """
        if not self._connected:
            raise NetBoxConnectionError("Not connected to NetBox")

        try:
            logger.debug("Verifying NetBox connectivity and API permissions")
            # Test actual API access with devices endpoint to validate permissions
            self.api.dcim.devices.count()
            logger.info("NetBox connectivity verified successfully")
            return True
        except Exception as e:
            error_msg = f"NetBox connectivity verification failed: {e}"
            logger.error(error_msg)
            raise NetBoxConnectionError(error_msg) from e

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

        In metalbox mode, additionally fetches devices with role=metalbox.

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

            # Normal filter logic
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

            # In metalbox mode, additionally fetch metalbox devices
            if self.config.reconciler_mode == "metalbox":
                logger.debug("Metalbox mode: fetching additional metalbox devices")
                metalbox_filters = (
                    self._device_filter._apply_metalbox_filter_modifications(
                        filter_list
                    )
                )

                for metalbox_filter in metalbox_filters:
                    logger.debug(
                        f"Fetching metalbox devices with filter: {metalbox_filter}"
                    )
                    metalbox_devices = self.api.dcim.devices.filter(**metalbox_filter)
                    metalbox_devices_filtered = (
                        self._device_filter.filter_by_maintenance(metalbox_devices)
                    )

                    # Metalbox devices could be ironic or non-ironic, categorize them
                    for device in metalbox_devices_filtered:
                        if "managed-by-ironic" in [tag.slug for tag in device.tags]:
                            all_devices_with_ironic.append(device)
                        else:
                            all_devices_non_ironic.append(device)

                # In metalbox mode, additionally fetch switch devices
                logger.debug("Metalbox mode: fetching additional switch devices")
                switch_filters = self._device_filter._apply_switch_filter_modifications(
                    filter_list, self.config.dnsmasq_switch_roles
                )

                for switch_filter in switch_filters:
                    logger.debug(
                        f"Fetching switch devices with filter: {switch_filter}"
                    )
                    switch_devices = self.api.dcim.devices.filter(**switch_filter)
                    switch_devices_filtered = self._device_filter.filter_by_maintenance(
                        switch_devices
                    )

                    # Switch devices are not managed by ironic
                    all_devices_non_ironic.extend(switch_devices_filtered)

            # Remove duplicates
            unique_devices_with_ironic = self._device_filter.deduplicate_devices(
                all_devices_with_ironic
            )
            unique_devices_non_ironic = self._device_filter.deduplicate_devices(
                all_devices_non_ironic
            )

            logger.info(
                f"Retrieved {len(unique_devices_with_ironic)} devices with ironic tag, "
                f"{len(unique_devices_non_ironic)} devices without ironic tag"
            )

            return unique_devices_with_ironic, unique_devices_non_ironic

    def get_dnsmasq_devices(self) -> List[Any]:
        """Retrieve devices for dnsmasq configuration (broader than inventory).

        Uses tag-stripped filters so that any active device with a qualifying
        OOB interface gets a dnsmasq entry, regardless of device-level tags.
        Applies maintenance filtering but no provision-state or Ironic split.

        Returns:
            List of unique device objects for dnsmasq processing

        Raises:
            NetBoxAPIError: If device retrieval fails
        """
        with self.api_operation("get_dnsmasq_devices"):
            dnsmasq_filters = self._device_filter.build_dnsmasq_filters()
            all_devices = []
            for f in dnsmasq_filters:
                devices = self.api.dcim.devices.filter(**f)
                filtered = self._device_filter.filter_by_maintenance(devices)
                all_devices.extend(filtered)
            return self._device_filter.deduplicate_devices(all_devices)

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

    def get_all_oob_prefixes(self) -> List[Any]:
        """Get all networks with OOB role (no tag filter).

        Returns:
            List of prefix objects that have OOB role, regardless of tags
        """
        cache_key = "all_oob_prefixes"
        cached_result = self._cache_manager.get(cache_key)
        if cached_result is not None:
            return cached_result

        with self.api_operation("get_all_oob_prefixes"):
            prefixes = self.api.ipam.prefixes.filter(role="oob")
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
