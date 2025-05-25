# SPDX-License-Identifier: Apache-2.0

"""NetBox inventory generator for OSISM.

This script reads all required systems from the NetBox and writes them
into a form that can be evaluated by the Ansible Inventory Plugin INI.

This is a workaround to use the groups defined in cfg-generics without
having to import them into NetBox.
"""

import sys

from loguru import logger

from config import Config
from device_mapping import build_device_role_mapping
from dnsmasq_manager import DnsmasqManager
from inventory_manager import InventoryManager
from netbox_client import NetBoxClient
from utils import setup_logging, get_inventory_hostname


def main() -> None:
    """Main execution function."""
    setup_logging()

    try:
        # Load configuration
        config = Config.from_environment()

        logger.info(
            f"Generate the inventory from the Netbox ({config.reconciler_mode} mode)"
        )

        # Initialize components
        netbox_client = NetBoxClient(config)
        inventory_manager = InventoryManager(config, api=netbox_client.api)
        dnsmasq_manager = DnsmasqManager(config)

        # Fetch devices
        logger.info("Getting managed devices from NetBox. This could take some time.")
        devices_with_both_tags, devices_osism_only = netbox_client.get_managed_devices()
        all_devices = devices_with_both_tags + devices_osism_only
        logger.info(f"Found {len(all_devices)} total managed devices")

        # Extract data for ALL devices (regardless of mode)
        logger.info("Extracting data for all devices")
        for device in all_devices:
            logger.info(f"Extracting data for {get_inventory_hostname(device)}")
            if config.data_types:
                inventory_manager.extract_device_data(
                    device, data_types=config.data_types
                )
            else:
                inventory_manager.extract_device_config_context(device)

        # Filter devices based on reconciler mode for inventory writing
        if config.reconciler_mode == "metalbox":
            # In metalbox mode, only include devices with role "metalbox" in inventory
            inventory_devices = [
                device
                for device in all_devices
                if device.role
                and device.role.slug
                and device.role.slug.lower() == "metalbox"
            ]
            logger.info(
                f"Metalbox mode: {len(inventory_devices)} devices with role 'metalbox' will be included in inventory"
            )
        else:
            # In manager mode, include all devices
            inventory_devices = all_devices

        # Process devices and build role mapping (only for inventory devices)
        devices_to_roles = build_device_role_mapping(
            inventory_devices, config.ignored_roles
        )

        # Write device data files (only for inventory devices)
        for device in inventory_devices:
            logger.info(f"Writing files for {get_inventory_hostname(device)}")
            if config.data_types:
                inventory_manager.write_device_data(
                    device, data_types=config.data_types
                )
            else:
                inventory_manager.write_device_config_context(device)

        # Write host groups based on device roles
        logger.info("Generating host groups based on device roles")
        inventory_manager.write_host_groups(devices_to_roles)

        # Generate dnsmasq configuration
        logger.info("Generating dnsmasq configuration")
        # In metalbox mode, pass all_devices to collect OOB configs from all devices
        if config.reconciler_mode == "metalbox":
            dnsmasq_manager.write_dnsmasq_config(
                netbox_client, inventory_devices, all_devices
            )
        else:
            dnsmasq_manager.write_dnsmasq_config(netbox_client, inventory_devices)

        # Generate dnsmasq DHCP ranges
        logger.info("Generating dnsmasq DHCP ranges")
        dnsmasq_manager.write_dnsmasq_dhcp_ranges(netbox_client)

        logger.info("NetBox inventory generation completed successfully")

    except Exception as e:
        logger.error(f"Failed to generate inventory from NetBox: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
