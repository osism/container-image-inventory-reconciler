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

    def __init__(self, config, file_cache=None):
        super().__init__(config)
        self.file_cache = file_cache
        self.dhcp_generator = DHCPConfigGenerator(config)

    def process_devices(
        self,
        netbox_client: NetBoxClient,
        devices: List[Any],
        flush_cache: bool = False,
    ) -> None:
        """Process devices in manager mode.

        Writes individual dnsmasq configurations for each device.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
            flush_cache: Force regeneration of cached parameters
        """
        for device in devices:
            logger.debug(f"Checking OOB interface for device {device}")

            # Check if dnsmasq_parameters custom field exists and use it (unless cache flush is requested)
            cached_params = None
            if not flush_cache:
                # First check file cache if available
                if self.file_cache:
                    cached_params = self.file_cache.get_custom_field(
                        device.name, "dnsmasq_parameters"
                    )
                # Then check device custom fields
                if cached_params is None:
                    cached_params = device.custom_fields.get("dnsmasq_parameters")

            if cached_params and isinstance(cached_params, dict):
                logger.info(f"Using cached dnsmasq parameters for device {device.name}")
                # Extract the cached values
                if (
                    "dnsmasq_dhcp_hosts" in cached_params
                    and "dnsmasq_dhcp_macs" in cached_params
                ):
                    # Create the dnsmasq configuration data from cached values
                    dnsmasq_data = {}
                    hostname = get_inventory_hostname(device)
                    if cached_params["dnsmasq_dhcp_hosts"]:
                        dnsmasq_data[f"dnsmasq_dhcp_hosts__{hostname}"] = cached_params[
                            "dnsmasq_dhcp_hosts"
                        ]
                    if cached_params["dnsmasq_dhcp_macs"]:
                        dnsmasq_data[f"dnsmasq_dhcp_macs__{hostname}"] = cached_params[
                            "dnsmasq_dhcp_macs"
                        ]

                    # Write to device-specific file
                    self.write_dnsmasq_to_device(device, dnsmasq_data)
                    continue

            # Generate parameters if not cached
            ip_address, mac_address, vlan_id = netbox_client.get_device_oob_interface(
                device
            )

            if ip_address and mac_address:
                # Use inventory_hostname if set, otherwise use device name
                hostname = get_inventory_hostname(device)

                # Generate DHCP host entry (without VLAN tag in manager mode)
                entry = self.dhcp_generator.generate_dhcp_host_entry(
                    device, ip_address, mac_address
                )
                logger.debug(f"Added dnsmasq entry for {hostname}: {entry}")

                # Create the dnsmasq configuration data
                dnsmasq_data = {f"dnsmasq_dhcp_hosts__{hostname}": [entry]}

                # Prepare parameters for caching
                cache_params = {
                    "dnsmasq_dhcp_hosts": [entry],
                    "dnsmasq_dhcp_macs": [],
                }

                # Generate DHCP MAC entry
                mac_entry = self.dhcp_generator.generate_dhcp_mac_entry(
                    device, mac_address
                )
                if mac_entry:
                    dnsmasq_data[f"dnsmasq_dhcp_macs__{hostname}"] = [mac_entry]
                    cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                    logger.debug(f"Added dnsmasq MAC entry for {hostname}: {mac_entry}")

                # Cache the generated parameters
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

                # Write to device-specific file
                self.write_dnsmasq_to_device(device, dnsmasq_data)
