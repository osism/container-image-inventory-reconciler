# SPDX-License-Identifier: Apache-2.0

"""Manager mode handler for dnsmasq configuration."""

from typing import Any, List

from loguru import logger

from netbox_client import NetBoxClient
from utils import get_inventory_hostname
from .base import DnsmasqBase
from .dhcp_config import DHCPConfigGenerator


class ManagerModeHandler(DnsmasqBase):
    """Handles dnsmasq configuration for manager mode."""

    def __init__(self, config):
        super().__init__(config)
        self.dhcp_generator = DHCPConfigGenerator(config)

    def process_devices(
        self,
        netbox_client: NetBoxClient,
        devices: List[Any],
    ) -> None:
        """Process devices in manager mode.

        Writes individual dnsmasq configurations for each device.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
        """
        for device in devices:
            logger.debug(f"Checking OOB interface for device {device}")

            # Generate parameters from NetBox data
            ip_address, mac_address, vlan_id = netbox_client.get_device_oob_interface(
                device
            )

            if mac_address:
                # Use inventory_hostname if set, otherwise use device name
                hostname = get_inventory_hostname(device)

                # Prepare dnsmasq data and cache params
                dnsmasq_data = {}
                cache_params = {
                    "dnsmasq_dhcp_hosts": [],
                    "dnsmasq_dhcp_macs": [],
                }

                # Generate DHCP host entry only if we have both IP and MAC
                if ip_address:
                    entry = self.dhcp_generator.generate_dhcp_host_entry(
                        device, ip_address, mac_address
                    )
                    logger.debug(f"Added dnsmasq entry for {hostname}: {entry}")
                    dnsmasq_data[f"dnsmasq_dhcp_hosts__{hostname}"] = [entry]
                    cache_params["dnsmasq_dhcp_hosts"] = [entry]
                else:
                    logger.info(
                        f"Device {device.name} has MAC {mac_address} but no IP address - "
                        f"skipping dnsmasq_dhcp_hosts entry, will generate dnsmasq_dhcp_macs only"
                    )

                # Generate DHCP MAC entry (always generated when MAC exists)
                mac_entry = self.dhcp_generator.generate_dhcp_mac_entry(
                    device, mac_address
                )
                if mac_entry:
                    dnsmasq_data[f"dnsmasq_dhcp_macs__{hostname}"] = [mac_entry]
                    cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                    logger.debug(f"Added dnsmasq MAC entry for {hostname}: {mac_entry}")

                # Cache the generated parameters (even if only MAC entry exists)
                logger.info(
                    f"Caching generated dnsmasq parameters for device {device.name}"
                )
                success = netbox_client.update_device_custom_field(
                    device, "dnsmasq_parameters", cache_params
                )
                if not success:
                    logger.warning(
                        f"Failed to cache dnsmasq parameters for device {device.name}"
                    )

                # Write to device-specific file (only if we have at least one entry)
                if dnsmasq_data:
                    self.write_dnsmasq_to_device(device, dnsmasq_data)
