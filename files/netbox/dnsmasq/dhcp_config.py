# SPDX-License-Identifier: Apache-2.0

"""DHCP configuration generation for dnsmasq."""

import ipaddress
from typing import Any

from loguru import logger
import yaml

from config import Config
from netbox_client import NetBoxClient
from utils import get_inventory_hostname


class DHCPConfigGenerator:
    """Generates DHCP configurations for dnsmasq."""

    def __init__(self, config: Config):
        self.config = config

    def generate_dhcp_host_entry(
        self, device: Any, ip_address: str, mac_address: str, vlan_id: int = None
    ) -> str:
        """Generate a dnsmasq DHCP host entry.

        Args:
            device: NetBox device object
            ip_address: IP address for the device
            mac_address: MAC address for the device
            vlan_id: Optional VLAN ID for metalbox mode

        Returns:
            DHCP host entry string
        """
        # Format MAC address properly (lowercase with colons)
        mac_formatted = mac_address.lower()
        # Get inventory hostname for the device
        device_hostname = get_inventory_hostname(device)

        # Create dnsmasq DHCP host entry: "mac,hostname,ip[,set:vlanXXX]"
        if vlan_id and self.config.reconciler_mode == "metalbox":
            return f"{mac_formatted},{device_hostname},{ip_address},set:vlan{vlan_id}"
        else:
            return f"{mac_formatted},{device_hostname},{ip_address}"

    def generate_dhcp_mac_entry(self, device: Any, mac_address: str) -> str:
        """Generate a dnsmasq DHCP MAC entry.

        Args:
            device: NetBox device object
            mac_address: MAC address for the device

        Returns:
            DHCP MAC entry string or None if no tag available
        """
        # Format MAC address properly (lowercase with colons)
        mac_formatted = mac_address.lower()

        # Add dnsmasq_dhcp_macs using custom field or device type slug
        custom_dhcp_tag = device.custom_fields.get("dnsmasq_dhcp_tag")

        if custom_dhcp_tag:
            # Use custom field value if set
            return f"tag:{custom_dhcp_tag},{mac_formatted}"
        elif device.device_type and device.device_type.slug:
            # Fallback to device type slug
            device_type_slug = device.device_type.slug
            # Format: dhcp-mac=set:device-type-slug,mac-address
            return f"set:{device_type_slug},{mac_formatted}"

        return None

    def write_dhcp_ranges(self, netbox_client: NetBoxClient) -> None:
        """Generate and write dnsmasq DHCP ranges for OOB networks."""
        oob_networks = netbox_client.get_oob_networks()

        if not oob_networks:
            logger.debug("No OOB networks with managed-by-osism tag found")
            return

        dhcp_ranges = []

        for network in oob_networks:
            try:
                # Parse the network prefix
                net = ipaddress.ip_network(network.prefix)

                # Use network address as start IP
                start_ip = str(net.network_address)  # Use network address itself
                subnet_mask = str(net.netmask)

                # Add 'static' mode to only allow static assignments
                dhcp_range = f"{start_ip},static,{subnet_mask},12h"
                dhcp_ranges.append(dhcp_range)

                logger.debug(f"Generated DHCP range for {network.prefix}: {dhcp_range}")

            except Exception as e:
                logger.warning(f"Failed to process network {network.prefix}: {e}")
                continue

        if dhcp_ranges:
            # Write the dnsmasq DHCP ranges to group_vars/manager
            dnsmasq_dhcp_data = {"dnsmasq_dhcp_ranges": dhcp_ranges}

            # Ensure group_vars/manager directory exists
            group_vars_path = self.config.inventory_path / "group_vars" / "manager"
            group_vars_path.mkdir(parents=True, exist_ok=True)

            # Write to 999-netbox-dnsmasq-dhcp-range.yml
            output_file = group_vars_path / "999-netbox-dnsmasq-dhcp-range.yml"
            logger.debug(f"Writing DHCP ranges to {output_file}")

            with open(output_file, "w", encoding="utf-8") as fp:
                yaml.dump(
                    dnsmasq_dhcp_data, fp, Dumper=yaml.Dumper, default_flow_style=False
                )
