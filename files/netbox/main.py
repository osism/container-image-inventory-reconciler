# SPDX-License-Identifier: Apache-2.0

"""NetBox inventory generator for OSISM.

This script reads all required systems from the NetBox and writes them
into a form that can be evaluated by the Ansible Inventory Plugin INI.

This is a workaround to use the groups defined in cfg-generics without
having to import them into NetBox.
"""

import sys

from loguru import logger

from bulk_loader import BulkDataLoader
from config import Config
from device_mapping import build_device_role_mapping
from dnsmasq import DnsmasqManager
from gnmic import GnmicManager
from inventory import InventoryManager
from netbox_client import NetBoxClient
from parallel_processor import ParallelDeviceProcessor
from retry_utils import retry_on_api_error
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

        # Fetch devices
        logger.info("Getting managed devices from NetBox. This could take some time.")
        devices_with_both_tags, devices_osism_only = netbox_client.get_managed_devices()
        all_devices = devices_with_both_tags + devices_osism_only
        logger.info(f"Found {len(all_devices)} total managed devices")

        # Initialize bulk data loader and pre-load all interface and IP data
        logger.info("Initializing bulk data loader for optimized API access")
        bulk_loader = BulkDataLoader(netbox_client.api)
        device_ids = [device.id for device in all_devices]
        logger.info(f"Bulk loading interface and IP data for {len(device_ids)} devices")
        bulk_loader.load_device_data(device_ids)

        # Log bulk loader statistics
        stats = bulk_loader.get_statistics()
        logger.info(
            f"Bulk loader statistics: {stats['devices']} devices, "
            f"{stats['interfaces']} interfaces, {stats['ip_addresses']} IP addresses loaded"
        )

        # Initialize inventory manager with bulk loader
        inventory_manager = InventoryManager(
            config,
            api=netbox_client.api,
            netbox_client=netbox_client,
            bulk_loader=bulk_loader,
        )
        dnsmasq_manager = DnsmasqManager(config)
        gnmic_manager = GnmicManager(
            config,
            api=netbox_client.api,
            netbox_client=netbox_client,
            bulk_loader=bulk_loader,
        )

        # Extract data for ALL devices (regardless of mode)
        # Use parallel processing for improved performance
        logger.info("Extracting data for all devices")

        # Create parallel processor
        processor = ParallelDeviceProcessor(
            max_workers=config.max_workers, enabled=config.parallel_processing_enabled
        )

        # Define device processing function with retry logic
        @retry_on_api_error(
            max_retries=config.max_retries,
            initial_delay=config.retry_delay,
            backoff_factor=config.retry_backoff,
        )
        def process_single_device(device):
            """Process a single device with retry logic."""
            logger.debug(f"Extracting data for {device.name}")

            # Check if this device is a switch
            is_switch = (
                device.role
                and device.role.slug
                and device.role.slug.lower() in config.dnsmasq_switch_roles
            )

            if is_switch:
                # Switches only need dnsmasq_parameters (generated during dnsmasq config generation)
                # Extract only other data types if specified, excluding frr_parameters, netplan_parameters
                logger.debug(
                    f"Device {device.name} is a switch - skipping FRR/Netplan parameter generation"
                )
                if config.data_types:
                    data_types_for_extraction = [
                        dt
                        for dt in config.data_types
                        if dt not in ["frr_parameters", "netplan_parameters"]
                    ]
                else:
                    data_types_for_extraction = list()

                # In metalbox mode, also ensure gnmic_parameters are generated
                if config.reconciler_mode == "metalbox":
                    data_types_for_extraction.append("gnmic_parameters")

                if data_types_for_extraction:
                    inventory_manager.extract_device_data(
                        device, data_types=data_types_for_extraction
                    )
            else:
                # Non-switch devices: current behavior (FRR + Netplan + gnmic for metalbox)
                if config.data_types:
                    # Always include FRR and Netplan parameters for generation
                    data_types_for_extraction = list(
                        set(
                            config.data_types + ["frr_parameters", "netplan_parameters"]
                        )
                    )
                    # In metalbox mode, also ensure gnmic_parameters are generated
                    if config.reconciler_mode == "metalbox":
                        data_types_for_extraction.append("gnmic_parameters")
                    inventory_manager.extract_device_data(
                        device, data_types=data_types_for_extraction
                    )
                else:
                    # Even without data_types, ensure FRR and Netplan are generated
                    data_types_for_extraction = ["frr_parameters", "netplan_parameters"]
                    inventory_manager.extract_device_data(
                        device, data_types=data_types_for_extraction
                    )

        # Process all devices (parallel or sequential based on config)
        results = processor.process_devices(all_devices, process_single_device)

        # Log processing results
        logger.info(
            f"Device processing summary: "
            f"{results['completed']} completed, "
            f"{results['failed']} failed"
        )

        if results["failures"]:
            logger.warning(
                f"Failed to process {len(results['failures'])} devices: "
                f"{[f['device'] for f in results['failures']]}"
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

            # Write host groups based on device roles
            logger.info("Generating host groups based on device roles")
            inventory_manager.write_host_groups(devices_to_roles)

            # Fetch broader device list for dnsmasq (all active devices, no tag filter)
            logger.info("Fetching devices for dnsmasq configuration (broader filter)")
            dnsmasq_devices = netbox_client.get_dnsmasq_devices()
            logger.info(
                f"Found {len(dnsmasq_devices)} devices for dnsmasq configuration"
            )

            # Bulk-load interface data for any new devices not already loaded
            existing_device_ids = set(device_ids)
            new_dnsmasq_device_ids = [
                d.id for d in dnsmasq_devices if d.id not in existing_device_ids
            ]
            if new_dnsmasq_device_ids:
                logger.info(
                    f"Bulk loading data for {len(new_dnsmasq_device_ids)} additional dnsmasq devices"
                )
                bulk_loader.load_device_data(new_dnsmasq_device_ids)

            # Generate dnsmasq configuration
            logger.info("Generating dnsmasq configuration")
            if config.reconciler_mode == "metalbox":
                dnsmasq_manager.write_dnsmasq_config(
                    netbox_client, inventory_devices, dnsmasq_devices
                )
            else:
                dnsmasq_manager.write_dnsmasq_config(netbox_client, dnsmasq_devices)

            # Generate dnsmasq DHCP ranges
            logger.info("Generating dnsmasq DHCP ranges")
            prefix_tags = getattr(dnsmasq_manager.metalbox_handler, "prefix_tags", None)
            dnsmasq_manager.write_dnsmasq_dhcp_ranges(
                netbox_client, prefix_tags=prefix_tags
            )

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

        # Log final bulk loader statistics
        final_stats = bulk_loader.get_statistics()
        logger.info(
            f"Final bulk loader statistics: {final_stats['devices']} devices, "
            f"{final_stats['interfaces']} interfaces, {final_stats['ip_addresses']} IP addresses"
        )

        logger.info("NetBox inventory generation completed successfully")

    except Exception as e:
        logger.error(f"Failed to generate inventory from NetBox: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
