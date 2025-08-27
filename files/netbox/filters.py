# SPDX-License-Identifier: Apache-2.0

"""Device filtering logic for NetBox queries."""

from typing import Any, Dict, List

from config import Config


class DeviceFilter:
    """Handles device filtering logic for NetBox queries."""

    def __init__(self, config: Config):
        self.config = config

    def normalize_filters(self) -> List[Dict[str, Any]]:
        """Normalize filter_inventory to always be a list.

        Returns:
            List of filter dictionaries
        """
        if isinstance(self.config.filter_inventory, dict):
            return [self.config.filter_inventory]
        return self.config.filter_inventory

    def build_ironic_filter(self, base_filter: Dict[str, Any]) -> Dict[str, Any]:
        """Build filter for devices managed by Ironic.

        Args:
            base_filter: Base filter dictionary

        Returns:
            Modified filter including Ironic-specific requirements
        """
        ironic_filter = base_filter.copy()

        # Handle tag parameter specially - it can be a string or list
        if "tag" in ironic_filter:
            existing_tags = ironic_filter["tag"]
            if isinstance(existing_tags, str):
                ironic_filter["tag"] = [existing_tags, "managed-by-ironic"]
            elif isinstance(existing_tags, list):
                if "managed-by-ironic" not in existing_tags:
                    ironic_filter["tag"] = existing_tags + ["managed-by-ironic"]
        else:
            ironic_filter["tag"] = ["managed-by-ironic"]

        # Add provision state filter for ironic devices only if NOT in metalbox mode and NOT ignoring provision state
        if (
            self.config.reconciler_mode != "metalbox"
            and not self.config.ignore_provision_state
        ):
            ironic_filter["cf_provision_state"] = ["active"]

        return ironic_filter

    def filter_by_maintenance(self, devices: List[Any]) -> List[Any]:
        """Filter out devices in maintenance mode.

        Args:
            devices: List of device objects

        Returns:
            List of devices not in maintenance
        """
        if self.config.ignore_maintenance_state:
            return devices

        return [
            device
            for device in devices
            if device.custom_fields.get("maintenance") is not True
        ]

    def filter_non_ironic_devices(self, devices: List[Any]) -> List[Any]:
        """Filter devices that don't have managed-by-ironic tag.

        Args:
            devices: List of device objects

        Returns:
            List of devices not managed by Ironic
        """
        filtered_devices = [
            device
            for device in devices
            if "managed-by-ironic" not in [tag.slug for tag in device.tags]
        ]

        if self.config.ignore_maintenance_state:
            return filtered_devices

        return [
            device
            for device in filtered_devices
            if device.custom_fields.get("maintenance") is not True
        ]

    def deduplicate_devices(self, devices: List[Any]) -> List[Any]:
        """Remove duplicate devices by ID.

        Args:
            devices: List of device objects

        Returns:
            List of unique devices
        """
        unique_devices = {dev.id: dev for dev in devices}
        return list(unique_devices.values())
