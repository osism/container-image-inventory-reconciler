# SPDX-License-Identifier: Apache-2.0

"""Interface handling for NetBox devices."""

from typing import Any, Optional, Tuple

from loguru import logger
import pynetbox

from .cache import CacheManager


class InterfaceHandler:
    """Handles interface-related operations for NetBox devices."""

    def __init__(self, api: pynetbox.api, cache_manager: Optional[CacheManager] = None):
        self.api = api
        self.cache = cache_manager or CacheManager()

    def get_oob_interface(
        self, device: Any
    ) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Get OOB management interface with IP and MAC address for a device.

        Args:
            device: NetBox device object

        Returns:
            A tuple of (ip_address, mac_address, vlan_id) or (None, None, None)
        """
        # Check cache first
        cache_key = f"oob_interface_{device.id}"
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result

        try:
            interfaces = self.api.dcim.interfaces.filter(device_id=device.id)

            for interface in interfaces:
                if not self._is_managed_oob_interface(interface):
                    continue

                mac_address = interface.mac_address
                if not mac_address:
                    continue

                vlan_id = self._get_vlan_id(interface)
                ip_info = self._get_interface_ip(interface)

                if ip_info:
                    result = (ip_info, mac_address, vlan_id)
                    self.cache.set(cache_key, result)
                    return result

            result = (None, None, None)
            self.cache.set(cache_key, result)
            return result

        except Exception as e:
            logger.warning(f"Failed to get OOB interface for device {device}: {e}")
            return None, None, None

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

    def _get_vlan_id(self, interface: Any) -> Optional[int]:
        """Get VLAN ID from interface if available.

        Args:
            interface: NetBox interface object

        Returns:
            VLAN ID or None
        """
        if hasattr(interface, "untagged_vlan") and interface.untagged_vlan:
            return interface.untagged_vlan.vid
        return None

    def _get_interface_ip(self, interface: Any) -> Optional[str]:
        """Get first IP address assigned to interface.

        Args:
            interface: NetBox interface object

        Returns:
            IP address without mask or None
        """
        ip_addresses = self.api.ipam.ip_addresses.filter(interface_id=interface.id)

        for ip in ip_addresses:
            return ip.address.split("/")[0]

        return None
