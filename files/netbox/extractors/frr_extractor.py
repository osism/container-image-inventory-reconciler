# SPDX-License-Identifier: Apache-2.0

"""FRR parameters extractor."""

from typing import Any, Dict, List, Optional

from loguru import logger

from bulk_loader import BulkDataLoader
from config import DEFAULT_FRR_SWITCH_ROLES
from .base_extractor import BaseExtractor
from .custom_field_extractor import CustomFieldExtractor


class ASNumberCalculator:
    """Handles AS number calculation from IP addresses."""

    @staticmethod
    def from_ipv4(ipv4_address: str, prefix: int = 4200) -> int:
        """Calculate AS number from IPv4 address.

        Args:
            ipv4_address: IPv4 address in format "192.168.45.123/32" or "192.168.45.123"
            prefix: Four-digit prefix for AS number (default: 4200)

        Returns:
            AS number calculated as prefix + 3rd octet (padded) + 4th octet (padded)
            Example: 192.168.45.123 with prefix 4200 -> 4200045123

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
            # Example: 192.168.45.123 -> 4200 + 045 + 123 = 4200045123
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
        - enabled status
        - NOT marked as management only (mgmt_only=False)

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
            and getattr(interface, "enabled", True)
            and not getattr(interface, "mgmt_only", False)
        )


class FRRExtractor(BaseExtractor):
    """Extracts FRR parameters from NetBox devices."""

    def __init__(
        self,
        api,
        netbox_client,
        bulk_loader: BulkDataLoader,
    ):
        """Initialize the extractor.

        Args:
            api: NetBox API instance (required for interface and device fetching)
            netbox_client: NetBox client instance for updating custom fields
            bulk_loader: BulkDataLoader instance for optimized API calls (required)
        """
        self.api = api
        self.netbox_client = netbox_client
        self.bulk_loader = bulk_loader
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

    def _get_loopback0_addresses(self, device: Any) -> Dict[str, Optional[str]]:
        """Get IPv4 and IPv6 addresses from loopback0 interface.

        Returns:
            Dictionary with 'ipv4' and 'ipv6' keys
        """
        result = {"ipv4": None, "ipv6": None}

        if not self.api:
            logger.warning("No API client available for loopback0 address lookup")
            return result

        try:
            # Get all interfaces using bulk_loader
            interfaces = self.bulk_loader.get_device_interfaces(device)

            loopback0 = None
            for interface in interfaces:
                if interface.name and interface.name.lower() == "loopback0":
                    loopback0 = interface
                    break

            if not loopback0:
                logger.debug(f"No loopback0 interface found for device {device.name}")
                return result

            # Get IP addresses assigned to loopback0 using bulk_loader
            ip_addresses = self.bulk_loader.get_interface_ip_addresses(loopback0)

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
                f"Found loopback0 addresses for {device.name}: IPv4={result['ipv4']}, IPv6={result['ipv6']}"
            )

        except Exception as e:
            logger.error(f"Error fetching loopback0 addresses for {device.name}: {e}")

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
            List of interface dictionaries with connection info and interface object
        """
        uplinks = []

        if not self.api:
            logger.warning("No API client available for interface lookup")
            return uplinks

        try:
            # Get interfaces using bulk_loader
            interfaces = self.bulk_loader.get_device_interfaces(device)

            for interface in interfaces:
                if not self.interface_filter.is_valid_uplink(interface):
                    continue

                # Get connected device from endpoints
                remote_device = self._get_remote_device(interface)
                if remote_device:
                    uplinks.append(
                        {
                            "interface": interface.label,
                            "remote_device": remote_device,
                            "interface_obj": interface,
                        }
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

    def _get_remote_interface(self, local_interface: Any) -> Optional[Any]:
        """Get the remote interface connected to a local interface.

        Args:
            local_interface: Local NetBox interface object

        Returns:
            Remote interface object or None
        """
        if (
            not hasattr(local_interface, "connected_endpoints")
            or not local_interface.connected_endpoints
        ):
            return None

        # connected_endpoints contains the remote interface(s)
        for endpoint in local_interface.connected_endpoints:
            return endpoint  # Return first endpoint

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
        if not hasattr(device, "role") or not device.role:
            return False

        return device.role.slug in switch_roles

    def extract(
        self,
        device: Any,
        local_as_prefix: int = 4200,
        switch_roles: List[str] = None,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Extract FRR parameters from device.

        First checks for manual frr_parameters custom field.
        If not found, generates parameters based on:
        - AS number from primary IPv4 of loopback0 (or frr_local_as custom field)
        - Loopback addresses from loopback0 interface
        - Uplinks from interfaces connected to Leaf switches

        Args:
            device: NetBox device object
            local_as_prefix: Four-digit prefix for AS number calculation (default: 4200)
            switch_roles: List of device role slugs to consider as switches for uplinks
            **kwargs: Additional parameters (unused)

        Returns:
            FRR parameters dictionary or None if no config found
        """
        if not self.api:
            return None

        result = {}

        # Get loopback0 addresses
        loopback0_addresses = self._get_loopback0_addresses(device)

        # Set loopback addresses
        if loopback0_addresses["ipv4"]:
            result["frr_loopback_v4"] = loopback0_addresses["ipv4"].split("/")[0]

            # Calculate or get local AS
            local_as = self._calculate_as_number(
                device, loopback0_addresses["ipv4"], local_as_prefix
            )
            if local_as:
                result["frr_local_as"] = local_as

        if loopback0_addresses["ipv6"]:
            result["frr_loopback_v6"] = loopback0_addresses["ipv6"]

        # Get FRR uplinks
        frr_uplinks = self._build_frr_uplinks(
            device, switch_roles or DEFAULT_FRR_SWITCH_ROLES, local_as_prefix
        )
        if frr_uplinks:
            result["frr_uplinks"] = frr_uplinks

        # Return None if no FRR configuration found
        if not result:
            return None

        # Write the generated parameters in the custom field
        if self.netbox_client:
            logger.info(f"Writing generated FRR parameters for device {device.name}")
            success = self.netbox_client.update_device_custom_field(
                device, "frr_parameters", result
            )
            if not success:
                logger.warning(
                    f"Failed to cache FRR parameters for device {device.name}"
                )

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
            remote_loopback0 = self._get_loopback0_addresses(remote_device)
            remote_as = self._calculate_as_number(
                remote_device, remote_loopback0.get("ipv4"), local_as_prefix
            )

            if remote_as:
                # Build base uplink configuration
                uplink_config = {
                    "interface": uplink["interface"],
                    "remote_as": remote_as,
                }

                # Add local_pref if custom field is set on either local or remote interface
                interface_obj = uplink.get("interface_obj")
                if interface_obj:
                    custom_field_extractor = CustomFieldExtractor()

                    # Check local interface
                    local_pref_local = custom_field_extractor.extract(
                        interface_obj, field_name="frr_local_pref"
                    )

                    # Check remote interface
                    remote_interface = self._get_remote_interface(interface_obj)
                    local_pref_remote = None
                    if remote_interface:
                        local_pref_remote = custom_field_extractor.extract(
                            remote_interface, field_name="frr_local_pref"
                        )

                    # Conflict resolution: use higher value if both are set
                    local_pref_final = None
                    if local_pref_local is not None and local_pref_remote is not None:
                        local_pref_final = max(local_pref_local, local_pref_remote)
                        logger.debug(
                            f"Both local ({local_pref_local}) and remote ({local_pref_remote}) "
                            f"frr_local_pref set for {uplink['interface']}, using {local_pref_final}"
                        )
                    elif local_pref_local is not None:
                        local_pref_final = local_pref_local
                    elif local_pref_remote is not None:
                        local_pref_final = local_pref_remote

                    if local_pref_final is not None:
                        uplink_config["local_pref"] = local_pref_final

                frr_uplinks.append(uplink_config)
            else:
                logger.warning(
                    f"Could not determine remote AS for {remote_device.name} "
                    f"connected to {device.name} via {uplink['interface']}"
                )

        return frr_uplinks
