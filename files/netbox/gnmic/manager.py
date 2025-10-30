# SPDX-License-Identifier: Apache-2.0

"""GNMIC manager for collecting and writing gnmic parameters in metalbox mode."""

from typing import Any, Dict, List

from loguru import logger

from bulk_loader import BulkDataLoader
from config import Config
from inventory import InventoryManager
from netbox_client import NetBoxClient


class GnmicManager:
    """Manages gnmic configuration for metalbox mode."""

    def __init__(
        self,
        config: Config,
        api,
        netbox_client,
        file_cache,
        bulk_loader: BulkDataLoader,
    ):
        """Initialize the GNMIC manager.

        Args:
            config: Configuration object
            api: NetBox API instance
            netbox_client: NetBox client instance
            file_cache: FileCache instance for persistent caching
            bulk_loader: BulkDataLoader instance for optimized data access
        """
        self.config = config
        self.api = api
        self.netbox_client = netbox_client
        self.file_cache = file_cache
        self.bulk_loader = bulk_loader
        self.inventory_manager = InventoryManager(
            config,
            api=api,
            netbox_client=netbox_client,
            file_cache=file_cache,
            bulk_loader=bulk_loader,
        )

    def write_gnmic_config(
        self,
        netbox_client: NetBoxClient,
        devices: List[Any],
        all_devices: List[Any] = None,
    ) -> None:
        """Write gnmic configuration for metalbox devices.

        In metalbox mode, collects gnmic_parameters from all devices with
        managed-by-metalbox tag and writes them to metalbox devices.

        Args:
            netbox_client: NetBox API client
            devices: List of metalbox devices to write configurations for
            all_devices: List of all devices to collect gnmic configs from
        """
        # Only process in metalbox mode
        if self.config.reconciler_mode != "metalbox":
            logger.debug("Not in metalbox mode, skipping gnmic configuration")
            return

        if not all_devices:
            logger.warning("No devices provided for gnmic configuration collection")
            return

        # Collect all gnmic parameters from devices with managed-by-metalbox tag
        all_gnmic_targets = {}

        for device in all_devices:
            logger.debug(f"Checking device {device.name} for gnmic configuration")

            # Extract gnmic parameters for this device
            gnmic_data = self.inventory_manager.data_extractor.extract_gnmic_parameters(
                device
            )

            if gnmic_data:
                logger.debug(
                    f"Found gnmic configuration for device {device.name}: {gnmic_data}"
                )
                # Merge all gnmic targets from this device
                for key, value in gnmic_data.items():
                    if key.startswith("gnmic_targets__"):
                        all_gnmic_targets[key] = value

        # Write collected gnmic targets to metalbox device(s)
        for device in devices:
            if (
                device.role
                and device.role.slug
                and device.role.slug.lower() == "metalbox"
            ):
                logger.info(
                    f"Writing gnmic configuration to metalbox device {device.name}"
                )

                # Create the gnmic configuration data
                gnmic_config_data = all_gnmic_targets.copy()

                # Write to metalbox device's host vars
                self._write_gnmic_to_device(device, gnmic_config_data)

                logger.info(
                    f"Wrote {len(all_gnmic_targets)} gnmic targets to metalbox device {device.name}"
                )

    def _write_gnmic_to_device(self, device: Any, gnmic_data: Dict[str, Any]) -> None:
        """Write gnmic configuration to a device's host vars.

        Args:
            device: NetBox device object
            gnmic_data: Dictionary containing gnmic configuration
        """
        try:
            # Write gnmic configuration to device's host vars
            self.inventory_manager.write_device_data_to_file(
                device, "gnmic_parameters", gnmic_data
            )
            logger.debug(
                f"Successfully wrote gnmic configuration to device {device.name}"
            )
        except Exception as e:
            logger.error(
                f"Failed to write gnmic configuration to device {device.name}: {e}"
            )
