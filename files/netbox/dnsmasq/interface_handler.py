# SPDX-License-Identifier: Apache-2.0

"""Interface handling for dnsmasq configuration."""

from typing import Any, List

from loguru import logger

from netbox_client import NetBoxClient


class InterfaceHandler:
    """Handles interface operations for dnsmasq configuration."""

    @staticmethod
    def get_virtual_interfaces_for_dnsmasq(
        device: Any,
        netbox_client: NetBoxClient,
        dhcp_hosts: List[str] = None,
        dhcp_options: List[str] = None,
        dynamic_hosts: List[str] = None,
    ) -> List[str]:
        """Get virtual interfaces with untagged VLANs for dnsmasq configuration.

        Returns a list of interface names (labels or names) that have:
        - The "managed-by-osism" tag
        - An untagged VLAN
        - Type = virtual
        - AND have corresponding DHCP entries for their VLAN

        Args:
            device: NetBox device object
            netbox_client: NetBox API client
            dhcp_hosts: List of DHCP host entries to check for VLAN tags
            dhcp_options: List of DHCP option entries to check for VLAN tags
            dynamic_hosts: List of dynamic host entries to check for interface names

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
            if not interface_name:
                continue

            vlan_id = interface.untagged_vlan.vid
            vlan_tag = f"vlan{vlan_id}"

            # Check if there are any DHCP entries for this VLAN
            has_dhcp_entries = False

            # Check dhcp_hosts for set:vlanXXX tags
            if dhcp_hosts:
                for entry in dhcp_hosts:
                    if f"set:{vlan_tag}" in entry:
                        has_dhcp_entries = True
                        break

            # Check dhcp_options for tag:vlanXXX
            if not has_dhcp_entries and dhcp_options:
                for entry in dhcp_options:
                    if f"tag:{vlan_tag}" in entry:
                        has_dhcp_entries = True
                        break

            # Check dynamic_hosts for interface name
            if not has_dhcp_entries and dynamic_hosts:
                for entry in dynamic_hosts:
                    if interface_name in entry:
                        has_dhcp_entries = True
                        break

            # Only add interface if there are DHCP entries for its VLAN
            if has_dhcp_entries:
                dnsmasq_interfaces.append(interface_name)
                logger.debug(
                    f"Found virtual interface {interface_name} with VLAN {vlan_id} for dnsmasq (has DHCP entries)"
                )
            else:
                logger.debug(
                    f"Skipping virtual interface {interface_name} with VLAN {vlan_id} - no DHCP entries found"
                )

        return dnsmasq_interfaces
