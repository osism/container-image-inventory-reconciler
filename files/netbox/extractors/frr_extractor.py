# SPDX-License-Identifier: Apache-2.0

"""FRR parameters extractor."""

from typing import Any, Dict, List, Optional

from loguru import logger

from .base_extractor import BaseExtractor
from .custom_field_extractor import CustomFieldExtractor


class ASNumberCalculator:
    """Handles AS number calculation from IP addresses."""

    @staticmethod
    def from_ipv4(ipv4_address: str, prefix: int = 42) -> int:
        """Calculate AS number from IPv4 address.

        Args:
            ipv4_address: IPv4 address in format "192.168.45.123/32" or "192.168.45.123"
            prefix: Two-digit prefix for AS number (default: 42)

        Returns:
            AS number calculated as prefix + 3rd octet (padded) + 4th octet (padded)
            Example: 192.168.45.123 with prefix 42 -> 42045123

        Raises:
            ValueError: If IP address format is invalid
        """
        try:
            # Remove CIDR notation if present
            ip_only = ipv4_address.split("/")[0]
            octets = ip_only.split(".")

            if len(octets) != 4:
                raise ValueError(f"Invalid IPv4 address format: {ipv4_address}")

            # AS = prefix + third octet (3 digits) + fourth octet (3 digits)
            # Example: 192.168.45.123 -> 42 + 045 + 123 = 42045123
            third_octet = int(octets[2])
            fourth_octet = int(octets[3])

            if not (0 <= third_octet <= 255 and 0 <= fourth_octet <= 255):
                raise ValueError(f"Invalid octet values in: {ipv4_address}")

            return int(f"{prefix}{third_octet:03d}{fourth_octet:03d}")
        except (IndexError, ValueError) as e:
            raise ValueError(f"Failed to calculate AS from {ipv4_address}: {str(e)}")


class InterfaceFilter:
    """Handles interface filtering logic."""

    @staticmethod
    def has_managed_tag(interface: Any) -> bool:
        """Check if interface has the managed-by-osism tag.

        Args:
            interface: NetBox interface object

        Returns:
            True if interface has the tag, False otherwise
        """
        if not hasattr(interface, "tags") or not interface.tags:
            return False

        tag_slugs = [tag.slug for tag in interface.tags]
        return "managed-by-osism" in tag_slugs

    @staticmethod
    def is_valid_uplink(interface: Any) -> bool:
        """Check if interface is a valid uplink.

        Interface must have:
        - managed-by-osism tag
        - a label
        - connected endpoints

        Args:
            interface: NetBox interface object

        Returns:
            True if interface is a valid uplink, False otherwise
        """
        return (
            InterfaceFilter.has_managed_tag(interface)
            and bool(interface.label)
            and hasattr(interface, "connected_endpoints")
            and bool(interface.connected_endpoints)
        )


class FRRExtractor(BaseExtractor):
    """Extracts FRR parameters from NetBox devices."""

    def __init__(self, api=None):
        """Initialize the extractor.

        Args:
            api: NetBox API instance (required for interface and device fetching)
        """
        self.api = api
        self.as_calculator = ASNumberCalculator()
        self.interface_filter = InterfaceFilter()

    def _calculate_as_number(
        self, device: Any, ipv4_address: Optional[str], local_as_prefix: int
    ) -> Optional[int]:
        """Calculate or extract AS number for a device.

        First checks for custom field 'frr_local_as', then calculates from IPv4.

        Args:
            device: NetBox device object
            ipv4_address: IPv4 address to calculate from (if no custom field)
            local_as_prefix: Prefix for AS calculation

        Returns:
            AS number or None if cannot be determined
        """
        # Check for manual AS configuration
        custom_field_extractor = CustomFieldExtractor()
        manual_as = custom_field_extractor.extract(device, field_name="frr_local_as")
        if manual_as:
            return manual_as

        # Calculate from IPv4 if available
        if ipv4_address:
            try:
                return self.as_calculator.from_ipv4(ipv4_address, local_as_prefix)
            except ValueError as e:
                logger.warning(f"Failed to calculate AS for {device.name}: {e}")

        return None

    def _get_dummy0_addresses(self, device: Any) -> Dict[str, Optional[str]]:
        """Get IPv4 and IPv6 addresses from dummy0 interface.

        Returns:
            Dictionary with 'ipv4' and 'ipv6' keys
        """
        result = {"ipv4": None, "ipv6": None}

        if not self.api:
            logger.warning("No API client available for dummy0 address lookup")
            return result

        try:
            # Get dummy0 interface
            interfaces = self.api.dcim.interfaces.filter(
                device_id=device.id, name="dummy0"
            )

            if not interfaces:
                logger.debug(f"No dummy0 interface found for device {device.name}")
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

            logger.debug(
                f"Found dummy0 addresses for {device.name}: IPv4={result['ipv4']}, IPv6={result['ipv6']}"
            )

        except Exception as e:
            logger.error(f"Error fetching dummy0 addresses for {device.name}: {e}")

        return result

    def _get_uplink_interfaces(self, device: Any) -> List[Dict[str, Any]]:
        """Get all interfaces that could be uplinks.

        Returns interfaces that have:
        - managed-by-osism tag
        - a label
        - connected endpoints

        Args:
            device: NetBox device object

        Returns:
            List of interface dictionaries with connection info
        """
        uplinks = []

        if not self.api:
            logger.warning("No API client available for interface lookup")
            return uplinks

        try:
            interfaces = self.api.dcim.interfaces.filter(device_id=device.id)

            for interface in interfaces:
                if not self.interface_filter.is_valid_uplink(interface):
                    continue

                # Get connected device from endpoints
                remote_device = self._get_remote_device(interface)
                if remote_device:
                    uplinks.append(
                        {"interface": interface.label, "remote_device": remote_device}
                    )

        except Exception as e:
            logger.error(f"Error fetching interfaces for {device.name}: {e}")

        return uplinks

    def _get_remote_device(self, interface: Any) -> Optional[Any]:
        """Get the remote device connected to an interface.

        Args:
            interface: NetBox interface object

        Returns:
            Remote device object or None
        """
        for endpoint in interface.connected_endpoints:
            if hasattr(endpoint, "device"):
                return endpoint.device
        return None

    def _filter_switch_connections(
        self, uplinks: List[Dict[str, Any]], switch_roles: List[str]
    ) -> List[Dict[str, Any]]:
        """Filter uplinks to only include connections to switches.

        Args:
            uplinks: List of uplink connections
            switch_roles: Valid switch role slugs

        Returns:
            Filtered list of uplinks connected to switches
        """
        switch_uplinks = []

        for uplink in uplinks:
            remote_device = uplink["remote_device"]
            if self._is_switch_device(remote_device, switch_roles):
                switch_uplinks.append(uplink)

        return switch_uplinks

    def _is_switch_device(self, device: Any, switch_roles: List[str]) -> bool:
        """Check if a device has a switch role.

        Args:
            device: NetBox device object
            switch_roles: List of valid switch role slugs

        Returns:
            True if device has a switch role
        """
        if not hasattr(device, "device_role") or not device.device_role:
            return False

        return device.device_role.slug in switch_roles

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
            local_as = self._calculate_as_number(
                device, dummy0_addresses["ipv4"], local_as_prefix
            )
            if local_as:
                result["frr_local_as"] = local_as

        if dummy0_addresses["ipv6"]:
            result["frr_loopback_v6"] = dummy0_addresses["ipv6"]

        # Get FRR uplinks
        frr_uplinks = self._build_frr_uplinks(
            device, switch_roles or ["leaf", "access-leaf"], local_as_prefix
        )
        if frr_uplinks:
            result["frr_uplinks"] = frr_uplinks

        # Return None if no FRR configuration found
        if not result:
            return None

        return result

    def _build_frr_uplinks(
        self, device: Any, switch_roles: List[str], local_as_prefix: int
    ) -> List[Dict[str, Any]]:
        """Build FRR uplink configurations.

        Args:
            device: NetBox device object
            switch_roles: List of valid switch role slugs
            local_as_prefix: AS number prefix for calculation

        Returns:
            List of FRR uplink configurations
        """
        frr_uplinks = []

        # Get all potential uplinks
        uplinks = self._get_uplink_interfaces(device)

        # Filter to only switch connections
        switch_uplinks = self._filter_switch_connections(uplinks, switch_roles)

        for uplink in switch_uplinks:
            # Get remote AS number
            remote_device = uplink["remote_device"]
            remote_dummy0 = self._get_dummy0_addresses(remote_device)
            remote_as = self._calculate_as_number(
                remote_device, remote_dummy0.get("ipv4"), local_as_prefix
            )

            if remote_as:
                frr_uplinks.append(
                    {"interface": uplink["interface"], "remote_as": remote_as}
                )
            else:
                logger.warning(
                    f"Could not determine remote AS for {remote_device.name} "
                    f"connected to {device.name} via {uplink['interface']}"
                )

        return frr_uplinks
