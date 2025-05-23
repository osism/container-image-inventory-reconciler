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
    def extract_all_data(device: Any) -> Dict[str, Any]:
        """Extract all configured data types from a device."""
        return {
            "config_context": DeviceDataExtractor.extract_config_context(device),
            "primary_ip": DeviceDataExtractor.extract_primary_ip(device),
            "netplan_parameters": DeviceDataExtractor.extract_custom_field(
                device, "netplan_parameters"
            ),
            "frr_parameters": DeviceDataExtractor.extract_custom_field(
                device, "frr_parameters"
            ),
        }
