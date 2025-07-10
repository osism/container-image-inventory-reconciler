# SPDX-License-Identifier: Apache-2.0

"""Device data extraction functionality."""

from typing import Any, Dict, List

from extractors import (
    ConfigContextExtractor,
    CustomFieldExtractor,
    FRRExtractor,
    GNMIExtractor,
    NetplanExtractor,
    PrimaryIPExtractor,
)


class DeviceDataExtractor:
    """Extracts various data fields from NetBox devices."""

    def __init__(self, api=None, netbox_client=None, file_cache=None):
        """Initialize extractors.

        Args:
            api: NetBox API instance (required for NetplanExtractor, FRRExtractor, and GNMIExtractor)
            netbox_client: NetBox client instance for updating custom fields
            file_cache: FileCache instance for persistent caching
        """
        self.config_context_extractor = ConfigContextExtractor()
        self.primary_ip_extractor = PrimaryIPExtractor()
        self.custom_field_extractor = CustomFieldExtractor(file_cache=file_cache)
        self.netplan_extractor = NetplanExtractor(
            api=api, netbox_client=netbox_client, file_cache=file_cache
        )
        self.frr_extractor = FRRExtractor(
            api=api, netbox_client=netbox_client, file_cache=file_cache
        )
        self.gnmi_extractor = GNMIExtractor(
            api=api, netbox_client=netbox_client, file_cache=file_cache
        )
        self.netbox_client = netbox_client
        self.file_cache = file_cache

    def extract_config_context(self, device: Any) -> Dict[str, Any]:
        """Extract config context from device."""
        return self.config_context_extractor.extract(device)

    def extract_custom_field(self, device: Any, field_name: str) -> Any:
        """Extract a specific custom field from device."""
        return self.custom_field_extractor.extract(device, field_name=field_name)

    def extract_primary_ip(self, device: Any) -> Any:
        """Extract primary IP address from device, prioritizing IPv4 over IPv6."""
        return self.primary_ip_extractor.extract(device)

    def extract_netplan_parameters(
        self,
        device: Any,
        default_mtu: int = 9100,
        switch_roles: List[str] = None,
        flush_cache: bool = False,
        reconciler_mode: str = "manager",
    ) -> Any:
        """Extract netplan parameters, combining manual and auto-generated config."""
        return self.netplan_extractor.extract(
            device,
            default_mtu=default_mtu,
            switch_roles=switch_roles,
            flush_cache=flush_cache,
            reconciler_mode=reconciler_mode,
        )

    def extract_frr_parameters(
        self,
        device: Any,
        local_as_prefix: int = 42,
        switch_roles: List[str] = None,
        flush_cache: bool = False,
    ) -> Any:
        """Extract FRR parameters, combining manual and auto-generated config."""
        return self.frr_extractor.extract(
            device,
            local_as_prefix=local_as_prefix,
            switch_roles=switch_roles,
            flush_cache=flush_cache,
        )

    def extract_dnsmasq_parameters(self, device: Any) -> Any:
        """Extract dnsmasq parameters from custom field."""
        return self.custom_field_extractor.extract(
            device, field_name="dnsmasq_parameters"
        )

    def extract_gnmi_parameters(self, device: Any) -> Any:
        """Extract GNMI parameters for metalbox-managed switches."""
        return self.gnmi_extractor.extract(device)

    def extract_all_data(
        self,
        device: Any,
        default_mtu: int = 9100,
        local_as_prefix: int = 42,
        switch_roles: List[str] = None,
        flush_cache: bool = False,
        reconciler_mode: str = "manager",
    ) -> Dict[str, Any]:
        """Extract all configured data types from a device."""
        return {
            "config_context": self.extract_config_context(device),
            "primary_ip": self.extract_primary_ip(device),
            "netplan_parameters": self.extract_netplan_parameters(
                device, default_mtu, switch_roles, flush_cache, reconciler_mode
            ),
            "frr_parameters": self.extract_frr_parameters(
                device, local_as_prefix, switch_roles, flush_cache
            ),
            "dnsmasq_parameters": self.extract_dnsmasq_parameters(device),
            "gnmi_parameters": self.extract_gnmi_parameters(device),
        }
