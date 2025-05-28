# SPDX-License-Identifier: Apache-2.0

"""Main dnsmasq manager that coordinates different modes and operations."""

from typing import Any, List

from config import Config
from netbox_client import NetBoxClient
from .dhcp_config import DHCPConfigGenerator
from .manager_mode import ManagerModeHandler
from .metalbox_mode import MetalboxModeHandler


class DnsmasqManager:
    """Manages dnsmasq configuration for devices."""

    def __init__(self, config: Config, file_cache=None):
        self.config = config
        self.file_cache = file_cache
        self.dhcp_generator = DHCPConfigGenerator(config)
        self.manager_handler = ManagerModeHandler(config, file_cache=file_cache)
        self.metalbox_handler = MetalboxModeHandler(config, file_cache=file_cache)

    def write_dnsmasq_config(
        self,
        netbox_client: NetBoxClient,
        devices: List[Any],
        all_devices: List[Any] = None,
        flush_cache: bool = False,
    ) -> None:
        """Write dnsmasq DHCP configuration for devices with OOB management interfaces.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
            all_devices: List of all devices (used in metalbox mode to collect all OOB configs)
            flush_cache: Force regeneration of cached parameters
        """
        # In metalbox mode, collect all dnsmasq entries to write to metalbox device
        if self.config.reconciler_mode == "metalbox" and all_devices:
            self.metalbox_handler.process_devices(
                netbox_client, devices, all_devices, flush_cache
            )
        else:
            # Original behavior for manager mode
            self.manager_handler.process_devices(netbox_client, devices, flush_cache)

    def write_dnsmasq_dhcp_ranges(self, netbox_client: NetBoxClient) -> None:
        """Generate and write dnsmasq DHCP ranges for OOB networks.

        Args:
            netbox_client: NetBox API client
        """
        self.dhcp_generator.write_dhcp_ranges(netbox_client)
