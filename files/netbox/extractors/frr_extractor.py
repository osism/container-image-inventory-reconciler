# SPDX-License-Identifier: Apache-2.0

"""FRR parameters extractor."""

from typing import Any, Dict, List, Optional

from .base_extractor import BaseExtractor
from .custom_field_extractor import CustomFieldExtractor


class FRRExtractor(BaseExtractor):
    """Extracts FRR parameters from NetBox devices."""

    def __init__(self, api=None):
        """Initialize the extractor.

        Args:
            api: NetBox API instance (required for interface and device fetching)
        """
        self.api = api

    def _calculate_as_from_ipv4(
        self, ipv4_address: str, local_as_prefix: int = 42
    ) -> int:
        """Calculate AS number from IPv4 address.

        Args:
            ipv4_address: IPv4 address in format "192.168.45.123/32"
            local_as_prefix: Two-digit prefix for AS number (default: 42)

        Returns:
            AS number calculated as prefix + 3rd octet (padded) + 4th octet (padded)
            Example: 192.168.45.123 with prefix 42 -> 42045123
        """
        # Remove CIDR notation if present
        ip_only = ipv4_address.split("/")[0]
        octets = ip_only.split(".")

        # AS = prefix + third octet (3 digits) + fourth octet (3 digits)
        # Example: 192.168.45.123 -> 42 + 045 + 123 = 42045123
        third_octet = int(octets[2])
        fourth_octet = int(octets[3])
        return int(f"{local_as_prefix}{third_octet:03d}{fourth_octet:03d}")

    def _get_dummy0_addresses(self, device: Any) -> Dict[str, Optional[str]]:
        """Get IPv4 and IPv6 addresses from dummy0 interface.

        Returns:
            Dictionary with 'ipv4' and 'ipv6' keys
        """
        result = {"ipv4": None, "ipv6": None}

        try:
            # Get dummy0 interface
            interfaces = self.api.dcim.interfaces.filter(
                device_id=device.id, name="dummy0"
            )

            if not interfaces:
                return result

            dummy0 = interfaces[0]

            # Get IP addresses assigned to dummy0
            ip_addresses = self.api.ipam.ip_addresses.filter(interface_id=dummy0.id)

            for ip in ip_addresses:
                if not ip.address:
                    continue

                # Check if IPv4 or IPv6
                if ":" in ip.address and not result["ipv6"]:
                    # IPv6 address - take the first one found
                    result["ipv6"] = ip.address.split("/")[0]
                elif "." in ip.address and not result["ipv4"]:
                    # IPv4 address - take the first one found
                    result["ipv4"] = ip.address

        except Exception:
            pass

        return result

    def _get_connected_leaf_devices(
        self, device: Any, switch_roles: List[str] = None
    ) -> list:
        """Get interfaces connected to switches with specified roles.

        Args:
            device: NetBox device object
            switch_roles: List of device role slugs to consider as switches
                         Defaults to ["leaf", "access-leaf"]

        Returns:
            List of dictionaries with interface and remote device information
        """
        connected_devices = []

        try:
            # Get all interfaces for the device
            interfaces = self.api.dcim.interfaces.filter(device_id=device.id)

            for interface in interfaces:
                # Check if interface has managed-by-osism tag and label
                if not hasattr(interface, "tags") or not interface.tags:
                    continue

                tag_slugs = [tag.slug for tag in interface.tags]
                if "managed-by-osism" not in tag_slugs:
                    continue

                if not interface.label:
                    continue

                # Check if interface is connected
                if (
                    not hasattr(interface, "connected_endpoints")
                    or not interface.connected_endpoints
                ):
                    continue

                # Get the connected device
                for endpoint in interface.connected_endpoints:
                    if hasattr(endpoint, "device"):
                        remote_device = endpoint.device

                        # Check if remote device role matches configured switch roles
                        if (
                            hasattr(remote_device, "device_role")
                            and remote_device.device_role
                        ):
                            role_slug = remote_device.device_role.slug
                            # Use provided switch roles or default to leaf and access-leaf
                            valid_roles = (
                                switch_roles
                                if switch_roles
                                else ["leaf", "access-leaf"]
                            )
                            if role_slug in valid_roles:
                                connected_devices.append(
                                    {
                                        "interface": interface.label,
                                        "remote_device": remote_device,
                                    }
                                )
                                break

        except Exception:
            pass

        return connected_devices

    def extract(
        self,
        device: Any,
        local_as_prefix: int = 42,
        switch_roles: List[str] = None,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Extract FRR parameters from device.

        First checks for manual frr_parameters custom field.
        If not found, generates parameters based on:
        - AS number from primary IPv4 of dummy0 (or frr_local_as custom field)
        - Loopback addresses from dummy0 interface
        - Uplinks from interfaces connected to Leaf switches

        Args:
            device: NetBox device object
            local_as_prefix: Two-digit prefix for AS number calculation (default: 42)
            switch_roles: List of device role slugs to consider as switches for uplinks
            **kwargs: Additional parameters (unused)

        Returns:
            FRR parameters dictionary or None if no config found
        """
        # Check if manual frr_parameters is set
        custom_field_extractor = CustomFieldExtractor()
        manual_params = custom_field_extractor.extract(
            device, field_name="frr_parameters"
        )
        if manual_params:
            return manual_params

        if not self.api:
            return None

        result = {}

        # Get dummy0 addresses
        dummy0_addresses = self._get_dummy0_addresses(device)

        # Set loopback addresses
        if dummy0_addresses["ipv4"]:
            result["frr_loopback_v4"] = dummy0_addresses["ipv4"].split("/")[0]

            # Calculate or get local AS
            frr_local_as = custom_field_extractor.extract(
                device, field_name="frr_local_as"
            )
            if frr_local_as:
                result["frr_local_as"] = frr_local_as
            else:
                result["frr_local_as"] = self._calculate_as_from_ipv4(
                    dummy0_addresses["ipv4"], local_as_prefix
                )

        if dummy0_addresses["ipv6"]:
            result["frr_loopback_v6"] = dummy0_addresses["ipv6"]

        # Get connected leaf devices
        connected_leafs = self._get_connected_leaf_devices(device, switch_roles)

        if connected_leafs:
            frr_uplinks = []

            for connection in connected_leafs:
                uplink = {"interface": connection["interface"]}

                # Get remote device's dummy0 IPv4 to calculate remote AS
                remote_dummy0 = self._get_dummy0_addresses(connection["remote_device"])
                if remote_dummy0["ipv4"]:
                    # Check if remote device has frr_local_as custom field
                    remote_frr_local_as = custom_field_extractor.extract(
                        connection["remote_device"], field_name="frr_local_as"
                    )
                    if remote_frr_local_as:
                        uplink["remote_as"] = remote_frr_local_as
                    else:
                        uplink["remote_as"] = self._calculate_as_from_ipv4(
                            remote_dummy0["ipv4"], local_as_prefix
                        )
                    frr_uplinks.append(uplink)

            if frr_uplinks:
                result["frr_uplinks"] = frr_uplinks

        # Return None if no FRR configuration found
        if not result:
            return None

        return result
