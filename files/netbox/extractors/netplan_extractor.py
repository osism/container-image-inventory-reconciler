# SPDX-License-Identifier: Apache-2.0

"""Netplan parameters extractor."""

from typing import Any, Dict, Optional

from .base_extractor import BaseExtractor
from .custom_field_extractor import CustomFieldExtractor


class NetplanExtractor(BaseExtractor):
    """Extracts netplan parameters from NetBox devices."""

    def extract(
        self, device: Any, default_mtu: int = 9100, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """Extract netplan parameters, combining manual and auto-generated config.

        Auto-generates config for interfaces that have:
        - The "managed-by-osism" tag
        - A primary MAC address (for regular interfaces)
        - A label configured (for regular interfaces)

        Args:
            device: NetBox device object
            default_mtu: Default MTU value for interfaces without explicit MTU
            **kwargs: Additional parameters (unused)

        Returns:
            Netplan parameters dictionary or None if no config found
        """
        # Check if manual netplan_parameters is set
        custom_field_extractor = CustomFieldExtractor()
        manual_params = custom_field_extractor.extract(
            device, field_name="netplan_parameters"
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
