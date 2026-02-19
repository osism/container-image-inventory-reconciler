# SPDX-License-Identifier: Apache-2.0

"""Device data extraction functionality."""

from typing import Any, Dict, List

from bulk_loader import BulkDataLoader
from extractors import (
    ConfigContextExtractor,
    CustomFieldExtractor,
    FRRExtractor,
    GnmicExtractor,
    NetplanExtractor,
    PrimaryIPExtractor,
)


class DeviceDataExtractor:
    """Extracts various data fields from NetBox devices."""

    def __init__(
        self,
        api,
        netbox_client,
        bulk_loader: BulkDataLoader,
    ):
        """Initialize extractors.

        Args:
            api: NetBox API instance (required for NetplanExtractor, FRRExtractor, and GnmicExtractor)
            netbox_client: NetBox client instance for updating custom fields
            bulk_loader: BulkDataLoader instance for optimized API calls (required)
        """
        self.config_context_extractor = ConfigContextExtractor()
        self.primary_ip_extractor = PrimaryIPExtractor()
        self.custom_field_extractor = CustomFieldExtractor()
        self.netplan_extractor = NetplanExtractor(
            api=api,
            netbox_client=netbox_client,
            bulk_loader=bulk_loader,
        )
        self.frr_extractor = FRRExtractor(
            api=api,
            netbox_client=netbox_client,
            bulk_loader=bulk_loader,
        )
        self.gnmic_extractor = GnmicExtractor(api=api, netbox_client=netbox_client)
        self.netbox_client = netbox_client
        self.bulk_loader = bulk_loader

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
        reconciler_mode: str = "manager",
    ) -> Any:
        """Extract netplan parameters from device interfaces.

        Auto-generates config and deep-merges overrides from
        device.local_context_data["netplan_parameters"] if present.
        """
        return self.netplan_extractor.extract(
            device,
            default_mtu=default_mtu,
            switch_roles=switch_roles,
            reconciler_mode=reconciler_mode,
        )

    def extract_frr_parameters(
        self,
        device: Any,
        local_as_prefix: int = 42,
        switch_roles: List[str] = None,
    ) -> Any:
        """Extract FRR parameters from device.

        Auto-generates config and deep-merges overrides from
        device.local_context_data["frr_parameters"] if present.
        """
        return self.frr_extractor.extract(
            device,
            local_as_prefix=local_as_prefix,
            switch_roles=switch_roles,
        )

    def extract_dnsmasq_parameters(self, device: Any) -> Any:
        """Extract dnsmasq parameters from custom field."""
        return self.custom_field_extractor.extract(
            device, field_name="dnsmasq_parameters"
        )

    def extract_gnmic_parameters(self, device: Any) -> Any:
        """Extract gnmicparameters for metalbox-managed switches."""
        return self.gnmic_extractor.extract(device)

    def extract_all_data(
        self,
        device: Any,
        default_mtu: int = 9100,
        local_as_prefix: int = 42,
        switch_roles: List[str] = None,
        reconciler_mode: str = "manager",
    ) -> Dict[str, Any]:
        """Extract all configured data types from a device."""
        return {
            "config_context": self.extract_config_context(device),
            "primary_ip": self.extract_primary_ip(device),
            "netplan_parameters": self.extract_netplan_parameters(
                device, default_mtu, switch_roles, reconciler_mode
            ),
            "frr_parameters": self.extract_frr_parameters(
                device, local_as_prefix, switch_roles
            ),
            "dnsmasq_parameters": self.extract_dnsmasq_parameters(device),
            "gnmic_parameters": self.extract_gnmic_parameters(device),
        }
