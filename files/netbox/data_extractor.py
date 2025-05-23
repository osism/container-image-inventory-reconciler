# SPDX-License-Identifier: Apache-2.0

"""Device data extraction functionality."""

from typing import Any, Dict

from extractors import (
    ConfigContextExtractor,
    CustomFieldExtractor,
    NetplanExtractor,
    PrimaryIPExtractor,
)


class DeviceDataExtractor:
    """Extracts various data fields from NetBox devices."""

    def __init__(self):
        """Initialize extractors."""
        self.config_context_extractor = ConfigContextExtractor()
        self.primary_ip_extractor = PrimaryIPExtractor()
        self.custom_field_extractor = CustomFieldExtractor()
        self.netplan_extractor = NetplanExtractor()

    def extract_config_context(self, device: Any) -> Dict[str, Any]:
        """Extract config context from device."""
        return self.config_context_extractor.extract(device)

    def extract_custom_field(self, device: Any, field_name: str) -> Any:
        """Extract a specific custom field from device."""
        return self.custom_field_extractor.extract(device, field_name=field_name)

    def extract_primary_ip(self, device: Any) -> Any:
        """Extract primary IP address from device, prioritizing IPv4 over IPv6."""
        return self.primary_ip_extractor.extract(device)

    def extract_netplan_parameters(self, device: Any, default_mtu: int = 9100) -> Any:
        """Extract netplan parameters, combining manual and auto-generated config."""
        return self.netplan_extractor.extract(device, default_mtu=default_mtu)

    def extract_all_data(self, device: Any, default_mtu: int = 9100) -> Dict[str, Any]:
        """Extract all configured data types from a device."""
        return {
            "config_context": self.extract_config_context(device),
            "primary_ip": self.extract_primary_ip(device),
            "netplan_parameters": self.extract_netplan_parameters(device, default_mtu),
            "frr_parameters": self.extract_custom_field(device, "frr_parameters"),
        }
