# SPDX-License-Identifier: Apache-2.0

"""Interface handling for dnsmasq configuration."""

from typing import Any, List

from loguru import logger

from netbox_client import NetBoxClient


class InterfaceHandler:
    """Handles interface operations for dnsmasq configuration."""

    @staticmethod
    def get_virtual_interfaces_for_dnsmasq(
        device: Any, netbox_client: NetBoxClient
    ) -> List[str]:
        """Get virtual interfaces with untagged VLANs for dnsmasq configuration.

        Returns a list of interface names (labels or names) that have:
        - The "managed-by-osism" tag
        - An untagged VLAN
        - Type = virtual

        Args:
            device: NetBox device object
            netbox_client: NetBox API client

        Returns:
            List of interface names for dnsmasq configuration
        """
        dnsmasq_interfaces = []

        # Get interfaces from device
        try:
            interfaces = netbox_client.api.dcim.interfaces.filter(device_id=device.id)
        except Exception as e:
            logger.warning(f"Failed to get interfaces for device {device.name}: {e}")
            return dnsmasq_interfaces

        if not interfaces:
            return dnsmasq_interfaces

        for interface in interfaces:
            # Check if this is a virtual interface
            if not (interface.type and interface.type.value == "virtual"):
                continue

            # Check if interface has managed-by-osism tag
            if not hasattr(interface, "tags") or not interface.tags:
                continue

            tag_slugs = [tag.slug for tag in interface.tags]
            if "managed-by-osism" not in tag_slugs:
                continue

            # Check if interface has untagged VLAN
            if not (hasattr(interface, "untagged_vlan") and interface.untagged_vlan):
                continue

            # Use label if set, otherwise use name
            interface_name = interface.label if interface.label else interface.name
            if interface_name:
                dnsmasq_interfaces.append(interface_name)
                logger.debug(
                    f"Found virtual interface {interface_name} with VLAN {interface.untagged_vlan.vid} for dnsmasq"
                )

        return dnsmasq_interfaces
