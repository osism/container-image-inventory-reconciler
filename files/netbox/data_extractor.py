# SPDX-License-Identifier: Apache-2.0

"""Device data extraction functionality."""

from typing import Any, Dict, Optional


class DeviceDataExtractor:
    """Extracts various data fields from NetBox devices."""

    @staticmethod
    def extract_config_context(device: Any) -> Dict[str, Any]:
        """Extract config context from device."""
        return device.config_context

    @staticmethod
    def extract_custom_field(device: Any, field_name: str) -> Any:
        """Extract a specific custom field from device."""
        custom_fields = device.custom_fields or {}
        return custom_fields.get(field_name)

    @staticmethod
    def extract_primary_ip(device: Any) -> Optional[str]:
        """Extract primary IP address from device, prioritizing IPv4 over IPv6."""
        # Check if device has primary_ip4
        if device.primary_ip4:
            return device.primary_ip4.address.split("/")[0]
        # Fall back to primary_ip6 if no IPv4 is available
        elif device.primary_ip6:
            return device.primary_ip6.address.split("/")[0]
        # Legacy fallback to primary_ip if neither is available
        elif device.primary_ip:
            return device.primary_ip.address.split("/")[0]
        return None

    @staticmethod
    def extract_netplan_parameters(
        device: Any, default_mtu: int = 9100
    ) -> Optional[Dict[str, Any]]:
        """Extract netplan parameters, combining manual and auto-generated config.

        Auto-generates config for interfaces that have:
        - The "managed-by-osism" tag
        - A primary MAC address (for regular interfaces)
        - A label configured (for regular interfaces)

        Returns manual netplan_parameters if set, otherwise auto-generated config.
        """
        # Check if manual netplan_parameters is set
        manual_params = DeviceDataExtractor.extract_custom_field(
            device, "netplan_parameters"
        )
        if manual_params:
            return manual_params

        # Get interfaces from device
        interfaces = device.interfaces.all()
        if not interfaces:
            return None

        network_ethernets = {}
        network_dummy_interfaces = []
        dummy0_interface = None

        for interface in interfaces:
            # Check if interface has managed-by-osism tag
            if not hasattr(interface, "tags") or not interface.tags:
                continue

            tag_names = [tag.name for tag in interface.tags.all()]
            if "managed-by-osism" not in tag_names:
                continue

            # Check for dummy0 interface
            if interface.name and interface.name.lower() == "dummy0":
                dummy0_interface = interface
                network_dummy_interfaces.append("dummy0")
                continue

            # Skip interfaces without MAC address or label
            if not interface.mac_address or not interface.label:
                continue

            # Use label as the interface name
            label = interface.label
            interface_config = {
                "match": {"macaddress": interface.mac_address.lower()},
                "set-name": label,
            }

            # Add MTU - use interface MTU if set, otherwise use default
            if hasattr(interface, "mtu") and interface.mtu:
                interface_config["mtu"] = interface.mtu
            else:
                interface_config["mtu"] = default_mtu

            network_ethernets[label] = interface_config

        # Add dummy0 configuration if found
        if dummy0_interface:
            dummy0_config = {}

            # Get all IP addresses assigned to dummy0
            addresses = []
            if hasattr(dummy0_interface, "ip_addresses"):
                ip_addresses = dummy0_interface.ip_addresses.all()
                for ip in ip_addresses:
                    if ip.address:
                        addresses.append(ip.address)

            if addresses:
                dummy0_config["addresses"] = addresses
                network_ethernets["dummy0"] = dummy0_config

        # Return None if no interfaces found
        if not network_ethernets and not network_dummy_interfaces:
            return None

        result = {}
        if network_ethernets:
            result["network_ethernets"] = network_ethernets
        if network_dummy_interfaces:
            result["network_dummy_interfaces"] = network_dummy_interfaces

        return result

    @staticmethod
    def extract_all_data(device: Any, default_mtu: int = 9100) -> Dict[str, Any]:
        """Extract all configured data types from a device."""
        return {
            "config_context": DeviceDataExtractor.extract_config_context(device),
            "primary_ip": DeviceDataExtractor.extract_primary_ip(device),
            "netplan_parameters": DeviceDataExtractor.extract_netplan_parameters(
                device, default_mtu
            ),
            "frr_parameters": DeviceDataExtractor.extract_custom_field(
                device, "frr_parameters"
            ),
        }
