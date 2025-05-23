# SPDX-License-Identifier: Apache-2.0

"""NetBox API client implementation."""

import time
from typing import Any, List, Optional, Tuple

from loguru import logger
import pynetbox

from config import Config


class NetBoxClient:
    """Client for NetBox API operations."""

    def __init__(self, config: Config):
        self.config = config
        self.api = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection to NetBox with retry logic."""
        logger.info(f"Connecting to NetBox {self.config.netbox_url}")

        for attempt in range(self.config.retry_attempts):
            try:
                self.api = pynetbox.api(
                    self.config.netbox_url, self.config.netbox_token
                )

                if self.config.ignore_ssl_errors:
                    self._configure_ssl_ignore()

                # Test connection
                self.api.dcim.sites.count()
                logger.debug("Successfully connected to NetBox")
                return

            except Exception as e:
                logger.warning(f"NetBox connection attempt {attempt + 1} failed: {e}")
                time.sleep(self.config.retry_delay)

        raise ConnectionError("Failed to connect to NetBox after all retry attempts")

    def _configure_ssl_ignore(self) -> None:
        """Configure SSL certificate verification ignoring."""
        import requests

        requests.packages.urllib3.disable_warnings()
        session = requests.Session()
        session.verify = False
        self.api.http_session = session

    def get_managed_devices(self) -> Tuple[List[Any], List[Any]]:
        """Retrieve managed devices from NetBox using configured filter(s).

        Returns:
            A tuple containing:
            - Devices with both base filter and managed-by-ironic tag
            - Devices with only base filter (not managed-by-ironic)
        """
        # Normalize filter_inventory to always be a list
        if isinstance(self.config.filter_inventory, dict):
            filter_list = [self.config.filter_inventory]
        else:
            filter_list = self.config.filter_inventory

        # Collect all devices from all filters
        all_devices_with_ironic = []
        all_devices_non_ironic = []

        for base_filter in filter_list:
            # First set: Nodes with base filter AND managed-by-ironic
            # For ironic-managed devices, we need to check provision_state
            ironic_filter = base_filter.copy()

            # Handle tag parameter specially - it can be a string or list
            if "tag" in ironic_filter:
                existing_tags = ironic_filter["tag"]
                if isinstance(existing_tags, str):
                    ironic_filter["tag"] = [existing_tags, "managed-by-ironic"]
                elif isinstance(existing_tags, list):
                    if "managed-by-ironic" not in existing_tags:
                        ironic_filter["tag"] = existing_tags + ["managed-by-ironic"]
            else:
                ironic_filter["tag"] = ["managed-by-ironic"]

            # Add provision state filter for ironic devices
            ironic_filter["cf_provision_state"] = ["active"]

            devices_with_ironic = self.api.dcim.devices.filter(**ironic_filter)

            # Filter out devices where cf_maintenance is True
            devices_with_ironic_filtered = [
                device
                for device in devices_with_ironic
                if device.custom_fields.get("maintenance") is not True
            ]

            # Second set: Nodes with base filter but NOT managed-by-ironic
            # For these, cf_provision_state is not evaluated
            devices_all = self.api.dcim.devices.filter(**base_filter)

            # Filter out devices that also have managed-by-ironic tag and where cf_maintenance is True
            devices_non_ironic_filtered = [
                device
                for device in devices_all
                if "managed-by-ironic" not in [tag.slug for tag in device.tags]
                and device.custom_fields.get("maintenance") is not True
            ]

            all_devices_with_ironic.extend(devices_with_ironic_filtered)
            all_devices_non_ironic.extend(devices_non_ironic_filtered)

        # Remove duplicates by device ID
        unique_devices_with_ironic = {dev.id: dev for dev in all_devices_with_ironic}
        unique_devices_non_ironic = {dev.id: dev for dev in all_devices_non_ironic}

        return list(unique_devices_with_ironic.values()), list(
            unique_devices_non_ironic.values()
        )

    def get_device_oob_interface(
        self, device: Any
    ) -> Tuple[Optional[str], Optional[str]]:
        """Get OOB management interface with IP and MAC address for a device.

        Returns:
            A tuple of (ip_address, mac_address) or (None, None) if not found.
        """
        try:
            # Get all interfaces for the device
            interfaces = self.api.dcim.interfaces.filter(device_id=device.id)

            for interface in interfaces:
                # Check if interface has 'managed-by-osism' tag and is management only
                if not interface.tags or not interface.mgmt_only:
                    continue

                has_managed_tag = any(
                    tag.slug == "managed-by-osism" for tag in interface.tags
                )
                if not has_managed_tag:
                    continue

                # Get MAC address
                mac_address = interface.mac_address
                if not mac_address:
                    continue

                # Get IP addresses for this interface
                ip_addresses = self.api.ipam.ip_addresses.filter(
                    interface_id=interface.id
                )

                for ip in ip_addresses:
                    # Return the first IP address found
                    ip_without_mask = ip.address.split("/")[0]
                    return ip_without_mask, mac_address

            return None, None

        except Exception as e:
            logger.warning(f"Failed to get OOB interface for device {device}: {e}")
            return None, None

    def get_oob_networks(self) -> List[Any]:
        """Get networks with managed-by-osism tag and OOB role.

        Returns:
            List of prefix objects that have managed-by-osism tag and OOB role.
        """
        try:
            # Get all prefixes with managed-by-osism tag and OOB role
            prefixes = self.api.ipam.prefixes.filter(
                tag=["managed-by-osism"], role="oob"
            )
            return list(prefixes)
        except Exception as e:
            logger.warning(f"Failed to get OOB networks: {e}")
            return []
