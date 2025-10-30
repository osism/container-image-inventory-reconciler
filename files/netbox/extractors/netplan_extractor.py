# SPDX-License-Identifier: Apache-2.0

"""Netplan parameters extractor."""

import re
from typing import Any, Dict, List, Optional

from loguru import logger

from bulk_loader import BulkDataLoader
from config import DEFAULT_FRR_SWITCH_ROLES, DEFAULT_METALBOX_IPV6
from .base_extractor import BaseExtractor
from .custom_field_extractor import CustomFieldExtractor


class NetplanExtractor(BaseExtractor):
    """Extracts netplan parameters from NetBox devices."""

    def __init__(
        self,
        api,
        netbox_client,
        file_cache,
        bulk_loader: BulkDataLoader,
    ):
        """Initialize the extractor.

        Args:
            api: NetBox API instance (required for interface fetching)
            netbox_client: NetBox client instance for updating custom fields
            file_cache: FileCache instance for persistent caching
            bulk_loader: BulkDataLoader instance for optimized API calls (required)
        """
        self.api = api
        self.netbox_client = netbox_client
        self.file_cache = file_cache
        self.bulk_loader = bulk_loader

    def _is_connected_to_switch(self, interface: Any, switch_roles: List[str]) -> bool:
        """Check if interface is connected to a device with switch role.

        Args:
            interface: NetBox interface object
            switch_roles: List of device role slugs considered as switches

        Returns:
            True if connected to a switch, False otherwise
        """
        if (
            not hasattr(interface, "connected_endpoints")
            or not interface.connected_endpoints
        ):
            return False

        for endpoint in interface.connected_endpoints:
            if hasattr(endpoint, "device") and endpoint.device:
                remote_device = endpoint.device
                if hasattr(remote_device, "role") and remote_device.role:
                    if remote_device.role.slug in switch_roles:
                        return True
        return False

    def _interface_has_ip_addresses(self, interface: Any) -> bool:
        """Check if interface has any IP addresses assigned.

        Args:
            interface: NetBox interface object

        Returns:
            True if interface has IP addresses, False otherwise
        """
        if not self.api:
            return False

        try:
            ip_addresses = self.bulk_loader.get_interface_ip_addresses(interface)
            return bool(ip_addresses)
        except Exception:
            return False

    def extract(
        self, device: Any, default_mtu: int = 9100, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """Extract netplan parameters, combining manual and auto-generated config.

        Auto-generates config for interfaces that have:
        - The "managed-by-osism" tag
        - A primary MAC address (for regular interfaces)
        - A label configured (for regular interfaces)

        For VLAN interfaces (type=virtual):
        - Must have "managed-by-osism" tag
        - Must have an untagged VLAN assigned
        - Must have a parent interface
        - Parent interface must also have "managed-by-osism" tag

        Args:
            device: NetBox device object
            default_mtu: Default MTU value for interfaces without explicit MTU
            **kwargs: Additional parameters including reconciler_mode

        Returns:
            Netplan parameters dictionary or None if no config found
        """
        # Check if device config context has _segment_default_mtu override
        effective_default_mtu = default_mtu
        if hasattr(device, "config_context") and device.config_context:
            segment_mtu = device.config_context.get("_segment_default_mtu")
            if segment_mtu is not None:
                try:
                    effective_default_mtu = int(segment_mtu)
                    logger.debug(
                        f"Using _segment_default_mtu={effective_default_mtu} from config context for device {device.name}"
                    )
                except (ValueError, TypeError):
                    logger.warning(
                        f"Invalid _segment_default_mtu value '{segment_mtu}' in config context for device {device.name}, using default {default_mtu}"
                    )
                    effective_default_mtu = default_mtu
        # Check flush_cache flag
        flush_cache = kwargs.get("flush_cache", False)

        # Check if manual netplan_parameters is set (unless cache flush is requested)
        if not flush_cache:
            # First check file cache if available
            if self.file_cache:
                cached_value = self.file_cache.get_custom_field(
                    device.name, "netplan_parameters"
                )
                if cached_value is not None:
                    return cached_value

            # Then check device custom fields
            custom_field_extractor = CustomFieldExtractor(file_cache=self.file_cache)
            manual_params = custom_field_extractor.extract(
                device, field_name="netplan_parameters"
            )
            if manual_params:
                return manual_params

        # Get interfaces from device using bulk_loader
        if not self.api:
            return None

        try:
            interfaces = self.bulk_loader.get_device_interfaces(device)
        except Exception:
            return None

        if not interfaces:
            return None

        network_ethernets = {}
        network_dummy_devices = {}
        network_vlans = {}
        network_vrfs = {}
        loopback0_interface = None

        for interface in interfaces:
            # Check if interface has managed-by-osism tag
            if not hasattr(interface, "tags") or not interface.tags:
                continue

            tag_slugs = [tag.slug for tag in interface.tags]
            if "managed-by-osism" not in tag_slugs:
                continue

            # Check if interface is assigned to a VRF
            if hasattr(interface, "vrf") and interface.vrf:
                try:
                    # Get VRF table ID from VRF name (e.g., "vrf42" -> 42)
                    vrf_table = None
                    if hasattr(interface.vrf, "name"):
                        vrf_name_str = str(interface.vrf.name)
                        # Match pattern like "vrf42", "vrf123", etc. (case insensitive)
                        match = re.match(r"^vrf(\d+)$", vrf_name_str, re.IGNORECASE)
                        if match:
                            vrf_table = int(match.group(1))
                            logger.debug(
                                f"Extracted table ID {vrf_table} from VRF name '{vrf_name_str}' for device {device.name}"
                            )

                    if vrf_table is not None:
                        vrf_table = int(vrf_table)
                        vrf_name = f"vrf{vrf_table}"

                        # Determine interface name to use
                        # For virtual interfaces, use name; for non-virtual, use label
                        if interface.type and interface.type.value == "virtual":
                            interface_name = interface.name
                        else:
                            interface_name = interface.label

                        if interface_name:
                            # Initialize VRF entry if not exists
                            if vrf_name not in network_vrfs:
                                network_vrfs[vrf_name] = {
                                    "table": vrf_table,
                                    "interfaces": [],
                                }

                            # Add interface to VRF's interface list
                            if (
                                interface_name
                                not in network_vrfs[vrf_name]["interfaces"]
                            ):
                                network_vrfs[vrf_name]["interfaces"].append(
                                    interface_name
                                )
                                logger.debug(
                                    f"Added interface {interface_name} to VRF {vrf_name} (table {vrf_table}) for device {device.name}"
                                )
                        else:
                            logger.warning(
                                f"Interface {interface.id} on device {device.name} has VRF assigned but no name/label"
                            )
                    else:
                        logger.warning(
                            f"Interface {interface.name or interface.id} on device {device.name} has VRF {interface.vrf.name} but no table ID found"
                        )
                except Exception as e:
                    logger.warning(
                        f"Error processing VRF for interface {interface.name or interface.id} on device {device.name}: {e}"
                    )

            # Check for loopback0 interface
            if interface.name and interface.name.lower() == "loopback0":
                loopback0_interface = interface
                continue

            # Check if this is a virtual interface (VLAN)
            if interface.type and interface.type.value == "virtual":
                # Check if interface has untagged VLAN and parent interface
                if hasattr(interface, "untagged_vlan") and interface.untagged_vlan:
                    if hasattr(interface, "parent") and interface.parent:
                        # Check if parent interface also has managed-by-osism tag
                        parent_has_tag = False
                        if hasattr(interface.parent, "tags") and interface.parent.tags:
                            parent_tag_slugs = [
                                tag.slug for tag in interface.parent.tags
                            ]
                            parent_has_tag = "managed-by-osism" in parent_tag_slugs

                        # Only include VLAN if parent also has the tag
                        if not parent_has_tag:
                            continue

                        vlan_name = (
                            interface.label if interface.label else interface.name
                        )
                        if vlan_name:
                            vlan_config = {
                                "id": interface.untagged_vlan.vid,
                                "link": (
                                    interface.parent.label
                                    if interface.parent.label
                                    else interface.parent.name
                                ),
                            }

                            # Use parent interface's MTU if available, otherwise use effective default
                            if (
                                hasattr(interface.parent, "mtu")
                                and interface.parent.mtu
                            ):
                                vlan_config["mtu"] = interface.parent.mtu
                            else:
                                vlan_config["mtu"] = effective_default_mtu

                            # Get IP addresses for this VLAN interface
                            addresses = []
                            try:
                                ip_addresses = (
                                    self.bulk_loader.get_interface_ip_addresses(
                                        interface
                                    )
                                )
                                for ip in ip_addresses:
                                    if ip.address:
                                        addresses.append(ip.address)
                            except Exception:
                                pass

                            if addresses:
                                vlan_config["addresses"] = addresses

                            # Check for interface-specific netplan_parameters custom field
                            if (
                                hasattr(interface, "custom_fields")
                                and interface.custom_fields
                            ):
                                interface_netplan_params = interface.custom_fields.get(
                                    "netplan_parameters"
                                )
                                if interface_netplan_params and isinstance(
                                    interface_netplan_params, dict
                                ):
                                    # Merge interface-specific parameters into the VLAN config
                                    vlan_config.update(interface_netplan_params)

                            network_vlans[vlan_name] = vlan_config
                continue

            # Skip interfaces without MAC address or label
            if not interface.mac_address or not interface.label:
                continue

            # Use label as the interface name
            label = interface.label
            interface_config = {
                "match": {"macaddress": interface.mac_address.lower()},
                "set-name": label,
            }

            # Check if interface is disabled
            is_enabled = getattr(interface, "enabled", True)
            if not is_enabled:
                # For disabled interfaces, only set basic config and mark as down
                interface_config["activation-mode"] = "off"
                network_ethernets[label] = interface_config
                continue

            # Add MTU - use interface MTU if set, otherwise use effective default
            if hasattr(interface, "mtu") and interface.mtu:
                interface_config["mtu"] = interface.mtu
            else:
                interface_config["mtu"] = effective_default_mtu

            # Get IP addresses for this interface
            addresses = []
            try:
                ip_addresses = self.bulk_loader.get_interface_ip_addresses(interface)
                for ip in ip_addresses:
                    if ip.address:
                        addresses.append(ip.address)
            except Exception:
                pass

            if addresses:
                interface_config["addresses"] = addresses

            # Check if this is a leaf interface (connected to a switch AND no IP addresses)
            switch_roles = kwargs.get("switch_roles", DEFAULT_FRR_SWITCH_ROLES)
            if self._is_connected_to_switch(
                interface, switch_roles
            ) and not self._interface_has_ip_addresses(interface):
                # Add leaf-specific parameters
                interface_config["link-local"] = ["ipv6"]
                interface_config["dhcp4"] = False
                interface_config["dhcp6"] = False

            # Check for interface-specific netplan_parameters custom field
            if hasattr(interface, "custom_fields") and interface.custom_fields:
                interface_netplan_params = interface.custom_fields.get(
                    "netplan_parameters"
                )
                if interface_netplan_params and isinstance(
                    interface_netplan_params, dict
                ):
                    # Merge interface-specific parameters into the interface config
                    interface_config.update(interface_netplan_params)

            network_ethernets[label] = interface_config

        # Add loopback0 configuration if found
        if loopback0_interface:
            loopback0_config = {}

            # Get all IP addresses assigned to loopback0 using bulk_loader
            addresses = []
            try:
                ip_addresses = self.bulk_loader.get_interface_ip_addresses(
                    loopback0_interface
                )
                for ip in ip_addresses:
                    if ip.address:
                        addresses.append(ip.address)
            except Exception:
                pass

            # In metalbox mode, always add the default metalbox IPv6 address to loopback0
            reconciler_mode = kwargs.get("reconciler_mode", "manager")
            if (
                reconciler_mode == "metalbox"
                and hasattr(device, "role")
                and device.role
            ):
                if device.role.slug == "metalbox":
                    if DEFAULT_METALBOX_IPV6 not in addresses:
                        addresses.append(DEFAULT_METALBOX_IPV6)
                        logger.info(
                            f"Added IPv6 address {DEFAULT_METALBOX_IPV6} to loopback0 for metalbox device {device.name}"
                        )

            if addresses:
                loopback0_config["addresses"] = addresses
                network_dummy_devices["loopback0"] = loopback0_config

        # Add metalbox dummy device if in metalbox mode and device has metalbox role
        reconciler_mode = kwargs.get("reconciler_mode", "manager")
        if reconciler_mode == "metalbox" and hasattr(device, "role") and device.role:
            if device.role.slug == "metalbox":
                logger.info(
                    f"Adding metalbox dummy interface for device {device.name} in metalbox mode"
                )
                # Configure metalbox dummy device with IP
                network_dummy_devices["metalbox"] = {"addresses": ["192.168.42.10/24"]}

        # Return None if no interfaces found
        if not network_ethernets and not network_dummy_devices and not network_vlans:
            return None

        result = {}
        if network_ethernets:
            result["network_ethernets"] = network_ethernets
        if network_dummy_devices:
            result["network_dummy_devices"] = network_dummy_devices
        if network_vlans:
            result["network_vlans"] = network_vlans
        if network_vrfs:
            result["network_vrfs"] = network_vrfs

        # Cache the generated parameters in the custom field
        if self.netbox_client:
            logger.info(
                f"Caching generated Netplan parameters for device {device.name}"
            )
            success = self.netbox_client.update_device_custom_field(
                device, "netplan_parameters", result
            )
            if not success:
                logger.warning(
                    f"Failed to cache Netplan parameters for device {device.name}"
                )

        return result
