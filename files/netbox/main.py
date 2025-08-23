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
from cluster_mapping import (
    build_cluster_mapping,
    build_cluster_inventory_groups,
    extract_cluster_config_contexts,
)
from dnsmasq import DnsmasqManager
from file_cache import FileCache
from gnmic import GnmicManager
from inventory import InventoryManager
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

        # Initialize file cache (always initialize to allow reading from existing cache)
        file_cache = FileCache()
        # Load cache from file if it exists, unless FLUSH_CACHE is true
        if not config.flush_cache:
            file_cache.load(flush_cache=False)

        # Initialize components
        netbox_client = NetBoxClient(config, file_cache=file_cache)
        inventory_manager = InventoryManager(
            config,
            api=netbox_client.api,
            netbox_client=netbox_client,
            file_cache=file_cache,
        )
        dnsmasq_manager = DnsmasqManager(config, file_cache=file_cache)
        gnmic_manager = GnmicManager(
            config,
            api=netbox_client.api,
            netbox_client=netbox_client,
            file_cache=file_cache,
        )

        # Fetch devices
        logger.info("Getting managed devices from NetBox. This could take some time.")
        devices_with_both_tags, devices_osism_only = netbox_client.get_managed_devices()
        all_devices = devices_with_both_tags + devices_osism_only
        logger.info(f"Found {len(all_devices)} total managed devices")

        # Extract data for ALL devices (regardless of mode)
        # Always ensure FRR and Netplan parameters are generated and written to NetBox
        logger.info("Extracting data for all devices")
        for device in all_devices:
            logger.info(f"Extracting data for {device.name}")
            if config.data_types:
                # Always include FRR and Netplan parameters for generation
                # They will be written to NetBox but only included in inventory if specified
                data_types_for_extraction = list(
                    set(config.data_types + ["frr_parameters", "netplan_parameters"])
                )
                # In metalbox mode, also ensure gnmic_parameters are generated
                if config.reconciler_mode == "metalbox":
                    data_types_for_extraction.append("gnmic_parameters")
                inventory_manager.extract_device_data(
                    device, data_types=data_types_for_extraction
                )
            else:
                # Even without data_types, ensure FRR and Netplan are generated
                data_types_for_extraction = [
                    "frr_parameters",
                    "netplan_parameters",
                ]
                # In metalbox mode, also ensure gnmic_parameters are generated
                if config.reconciler_mode == "metalbox":
                    data_types_for_extraction.append("gnmic_parameters")
                inventory_manager.extract_device_data(
                    device, data_types=data_types_for_extraction
                )

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

        # Build cluster mapping for inventory devices
        logger.info("Getting cluster and cluster group information from NetBox")
        clusters = netbox_client.get_clusters()
        cluster_groups = netbox_client.get_cluster_groups()

        cluster_mapping = build_cluster_mapping(
            inventory_devices, clusters, cluster_groups
        )
        cluster_inventory_groups = build_cluster_inventory_groups(cluster_mapping)
        cluster_config_contexts = extract_cluster_config_contexts(cluster_mapping)

        # Write inventory files only if INVENTORY_FROM_NETBOX is True
        if config.inventory_from_netbox:
            # Write device data files (only for inventory devices)
            for device in inventory_devices:
                logger.info(f"Writing files for {get_inventory_hostname(device)}")
                if config.data_types:
                    # In metalbox mode, always ensure config_context is written for metalbox devices
                    data_types_for_writing = config.data_types.copy()
                    if (
                        config.reconciler_mode == "metalbox"
                        and device.role
                        and device.role.slug == "metalbox"
                        and "config_context" not in data_types_for_writing
                    ):
                        data_types_for_writing.append("config_context")

                    inventory_manager.write_device_data(
                        device, data_types=data_types_for_writing
                    )
                else:
                    inventory_manager.write_device_config_context(device)

            # Write host groups based on device roles and clusters
            logger.info("Generating host groups based on device roles and clusters")
            inventory_manager.write_host_groups(
                devices_to_roles, cluster_inventory_groups
            )

            # Write cluster group_vars files for config contexts
            if cluster_config_contexts:
                logger.info("Writing cluster group_vars files for config contexts")
                inventory_manager.write_cluster_group_vars(cluster_config_contexts)

            # Generate dnsmasq configuration
            logger.info("Generating dnsmasq configuration")
            # In metalbox mode, pass all_devices to collect OOB configs from all devices
            if config.reconciler_mode == "metalbox":
                dnsmasq_manager.write_dnsmasq_config(
                    netbox_client, inventory_devices, all_devices, config.flush_cache
                )
            else:
                dnsmasq_manager.write_dnsmasq_config(
                    netbox_client, inventory_devices, flush_cache=config.flush_cache
                )

            # Generate dnsmasq DHCP ranges
            logger.info("Generating dnsmasq DHCP ranges")
            dnsmasq_manager.write_dnsmasq_dhcp_ranges(netbox_client)

            # Generate gnmic configuration (metalbox mode only)
            if config.reconciler_mode == "metalbox":
                logger.info("Generating gnmic configuration for metalbox mode")
                gnmic_manager.write_gnmic_config(
                    netbox_client, inventory_devices, all_devices
                )
        else:
            logger.info(
                "INVENTORY_FROM_NETBOX is False - skipping inventory file writing"
            )

        logger.info("NetBox inventory generation completed successfully")

        # Save file cache if enabled
        if config.write_cache and file_cache:
            file_cache.save()

    except Exception as e:
        logger.error(f"Failed to generate inventory from NetBox: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
