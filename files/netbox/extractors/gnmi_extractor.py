# SPDX-License-Identifier: Apache-2.0

"""GNMI parameters extractor for metalbox switches."""

from typing import Any, Dict, Optional

from loguru import logger

from .base_extractor import BaseExtractor


class GNMIExtractor(BaseExtractor):
    """Extracts GNMI parameters for switches managed by metalbox."""

    def extract(self, device: Any, **kwargs) -> Optional[Dict[str, Any]]:
        """Extract GNMI parameters for metalbox-managed switches.

        Args:
            device: NetBox device object
            **kwargs: Additional parameters - expects 'netbox_client' parameter

        Returns:
            Dictionary containing GNMI configuration for the switch, or None if not applicable
        """
        # Get NetBox client from kwargs
        self.netbox_client = kwargs.get("netbox_client")
        if not self.netbox_client:
            logger.error("NetBox client not provided in kwargs")
            return None

        # Check if device has managed-by-metalbox tag
        if not self._has_metalbox_tag(device):
            logger.debug(f"Device {device.name} does not have managed-by-metalbox tag")
            return None

        # Get hostname (from custom field or device name)
        hostname = self._get_hostname(device)

        # Get OOB IP address
        oob_ip = self._get_oob_ip(device)
        if not oob_ip:
            logger.warning(f"No OOB IP address found for device {device.name}")
            return None

        # Generate GNMI configuration
        gnmi_config = {
            f"gnmic_targets__{hostname}": {
                f"{oob_ip}:8080": {
                    "username": "admin",
                    "password": "YourPaSsWoRd",
                    "encoding": "json",
                    "subscriptions": ["all-interfaces"],
                }
            }
        }

        logger.debug(f"Generated GNMI config for {device.name}: {gnmi_config}")
        return gnmi_config

    def _has_metalbox_tag(self, device: Any) -> bool:
        """Check if device has managed-by-metalbox tag.

        Args:
            device: NetBox device object

        Returns:
            True if device has managed-by-metalbox tag, False otherwise
        """
        if not hasattr(device, "tags") or not device.tags:
            return False

        tag_slugs = [tag.slug for tag in device.tags]
        return "managed-by-metalbox" in tag_slugs

    def _get_hostname(self, device: Any) -> str:
        """Get hostname from custom field or device name.

        Args:
            device: NetBox device object

        Returns:
            Hostname string (inventory_hostname custom field or device name)
        """
        # Check for inventory_hostname custom field first
        if (
            hasattr(device, "custom_fields")
            and device.custom_fields
            and device.custom_fields.get("inventory_hostname")
        ):
            return device.custom_fields["inventory_hostname"]

        # Fall back to device name
        return device.name

    def _get_oob_ip(self, device: Any) -> Optional[str]:
        """Get OOB IP address for the device using the same approach as interfaces.py.

        Args:
            device: NetBox device object

        Returns:
            OOB IP address string (without subnet mask), or None if not found
        """
        try:
            # Get device ID for interface filtering
            device_id = device.id

            # Filter interfaces for this device
            interfaces = self.netbox_client.api.dcim.interfaces.filter(
                device_id=device_id
            )

            for interface in interfaces:
                # Check if this is a managed OOB interface
                if not self._is_managed_oob_interface(interface):
                    continue

                # Get IP addresses assigned to this interface
                ip_addresses = self.netbox_client.api.ipam.ip_addresses.filter(
                    interface_id=interface.id
                )

                for ip in ip_addresses:
                    if hasattr(ip, "address") and ip.address:
                        # Return the first IP address found (without subnet mask)
                        return ip.address.split("/")[0]

        except Exception as e:
            logger.warning(f"Error getting OOB IP for device {device.name}: {e}")

        return None

    def _is_managed_oob_interface(self, interface: Any) -> bool:
        """Check if interface is a managed OOB interface.

        Args:
            interface: NetBox interface object

        Returns:
            True if interface is managed OOB, False otherwise
        """
        if not interface.tags or not interface.mgmt_only:
            return False

        return any(tag.slug == "managed-by-osism" for tag in interface.tags)
