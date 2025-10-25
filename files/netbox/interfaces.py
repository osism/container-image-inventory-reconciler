# SPDX-License-Identifier: Apache-2.0

"""Interface handling for NetBox devices."""

from typing import Any, Optional, Tuple

from loguru import logger
import pynetbox

from cache import CacheManager


class InterfaceHandler:
    """Handles interface-related operations for NetBox devices."""

    def __init__(self, api: pynetbox.api, cache_manager: Optional[CacheManager] = None):
        self.api = api
        self.cache = cache_manager or CacheManager()

    def get_oob_interface(
        self, device: Any
    ) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Get OOB management interface with IP and MAC address for a device.

        For switches and other devices, this method will return the MAC address
        even if no IP address is assigned. This allows dnsmasq MAC entries to be
        generated for devices that only need MAC-based DHCP configuration.

        Args:
            device: NetBox device object

        Returns:
            A tuple of (ip_address, mac_address, vlan_id) where:
            - ip_address may be None if no IP is assigned to the interface
            - mac_address is the interface MAC (required, returns None if not found)
            - vlan_id is the VLAN ID from untagged_vlan, or None
            Returns (None, None, None) if no managed OOB interface with MAC is found
        """
        # Check cache first
        cache_key = f"oob_interface_{device.id}"
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result

        try:
            interfaces = self.api.dcim.interfaces.filter(device_id=device.id)

            # Track best match: prefer interface with IP, but accept one without IP
            best_match = None

            for interface in interfaces:
                if not self._is_managed_oob_interface(interface):
                    continue

                mac_address = interface.mac_address
                if not mac_address:
                    logger.debug(
                        f"Skipping interface {interface.name} (ID: {interface.id}) "
                        f"on device {device}: no MAC address"
                    )
                    continue

                vlan_id = self._get_vlan_id(interface)
                ip_info = self._get_interface_ip(interface)

                if ip_info:
                    # Found interface with both MAC and IP - this is ideal
                    result = (ip_info, mac_address, vlan_id)
                    self.cache.set(cache_key, result)
                    logger.debug(
                        f"Found OOB interface {interface.name} (ID: {interface.id}) "
                        f"on device {device} with MAC {mac_address} and IP {ip_info}"
                    )
                    return result
                else:
                    # Found interface with MAC but no IP - save as fallback
                    if best_match is None:
                        best_match = (None, mac_address, vlan_id)
                        logger.debug(
                            f"Found OOB interface {interface.name} (ID: {interface.id}) "
                            f"on device {device} with MAC {mac_address} but no IP (fallback)"
                        )

            # If we have a fallback match (MAC but no IP), use it
            if best_match is not None:
                result = best_match
                self.cache.set(cache_key, result)
                logger.info(
                    f"Using OOB interface on device {device} with MAC {best_match[1]} "
                    f"but no IP address (suitable for dnsmasq MAC entries)"
                )
                return result

            # No managed OOB interface found at all
            result = (None, None, None)
            self.cache.set(cache_key, result)
            logger.debug(
                f"No managed OOB interface with MAC address found for device {device}"
            )
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
