# SPDX-License-Identifier: Apache-2.0

"""Netplan parameters extractor."""

import re
from typing import Any, Dict, List, Optional

from loguru import logger

from bulk_loader import BulkDataLoader
from config import DEFAULT_FRR_SWITCH_ROLES, DEFAULT_METALBOX_IPV6
from utils import deep_merge
from .base_extractor import BaseExtractor


class NetplanExtractor(BaseExtractor):
    """Extracts netplan parameters from NetBox devices."""

    def __init__(
        self,
        api,
        netbox_client,
        bulk_loader: BulkDataLoader,
    ):
        """Initialize the extractor.

        Args:
            api: NetBox API instance (required for interface fetching)
            netbox_client: NetBox client instance for updating custom fields
            bulk_loader: BulkDataLoader instance for optimized API calls (required)
        """
        self.api = api
        self.netbox_client = netbox_client
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
        """Extract netplan parameters from device interfaces.

        Auto-generates config for interfaces that have:
        - The "managed-by-osism" tag
        - A primary MAC address (for regular interfaces)
        - A label configured (for regular interfaces)

        For VLAN interfaces (type=virtual):
        - Must have "managed-by-osism" tag
        - Must have an untagged VLAN assigned
        - Must have a parent interface
        - Parent interface must also have "managed-by-osism" tag

        For VXLAN interfaces (name pattern: vxlan<VNI>, e.g. vxlan42):
        - Must have "managed-by-osism" tag
        - If assigned to a VRF, the interface is added to the VRF's interface list

        If device.local_context_data contains a "netplan_parameters" key, its values
        are deep-merged into the auto-generated parameters. Values from
        local_context_data take precedence on conflicts.

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
        network_tunnels = {}
        loopback0_interface = None

        # Track VXLAN interfaces for later processing (need loopback0 IP first)
        # Format: {interface_name: interface_object}
        vxlan_interfaces = {}

        # Track VRF assignments during interface processing
        # Format: {interface_id: (vrf_name, vrf_table)}
        interface_vrf_assignments = {}

        for interface in interfaces:
            # Check if interface has managed-by-osism tag
            if not hasattr(interface, "tags") or not interface.tags:
                continue

            tag_slugs = [tag.slug for tag in interface.tags]
            if "managed-by-osism" not in tag_slugs:
                continue

            # Skip management-only (out-of-band) interfaces
            if getattr(interface, "mgmt_only", False):
                logger.debug(
                    f"Skipping mgmt_only interface {interface.name or interface.id} on device {device.name}"
                )
                continue

            # Store VRF assignment for later processing (after interface validation)
            if hasattr(interface, "vrf") and interface.vrf:
                try:
                    # Check if VRF name starts with "vrf" (case insensitive)
                    if hasattr(interface.vrf, "name"):
                        vrf_name_str = str(interface.vrf.name)
                        # Accept any VRF name starting with "vrf" (case insensitive)
                        if vrf_name_str.lower().startswith("vrf"):
                            # Use the VRF name directly from Netbox
                            vrf_name = vrf_name_str
                            vrf_table = None

                            # First try to extract table ID from VRF name (pattern: vrfN)
                            name_match = re.match(
                                r"^vrf(\d+)$", vrf_name_str, re.IGNORECASE
                            )
                            if name_match:
                                vrf_table = int(name_match.group(1))
                                logger.debug(
                                    f"Extracted table ID {vrf_table} from VRF name {vrf_name} on device {device.name}"
                                )
                            else:
                                # Fallback: Extract table ID from Route Distinguisher (RD)
                                if hasattr(interface.vrf, "rd") and interface.vrf.rd:
                                    rd_str = str(interface.vrf.rd)
                                    # RD format: "ASN:number", "IP:number", or plain number
                                    try:
                                        if ":" in rd_str:
                                            vrf_table = int(rd_str.split(":")[-1])
                                        else:
                                            vrf_table = int(rd_str)
                                        logger.debug(
                                            f"Extracted table ID {vrf_table} from RD '{rd_str}' for VRF {vrf_name} on device {device.name}"
                                        )
                                    except ValueError:
                                        logger.warning(
                                            f"Could not extract table ID from RD '{rd_str}' for VRF {vrf_name} on device {device.name}"
                                        )

                            if vrf_table is None:
                                logger.warning(
                                    f"VRF {vrf_name} on device {device.name} has no table ID in name and no valid RD"
                                )
                            else:
                                # Store VRF assignment for processing after interface validation
                                interface_vrf_assignments[interface.id] = (
                                    vrf_name,
                                    vrf_table,
                                )
                                logger.debug(
                                    f"Stored VRF assignment for interface {interface.name or interface.id}: {vrf_name} (table {vrf_table}) on device {device.name}"
                                )
                        else:
                            logger.warning(
                                f"Interface {interface.name or interface.id} on device {device.name} has VRF {vrf_name_str} but name doesn't start with 'vrf'"
                            )
                    else:
                        logger.warning(
                            f"Interface {interface.name or interface.id} on device {device.name} has VRF but no name attribute"
                        )
                except Exception as e:
                    logger.warning(
                        f"Error storing VRF assignment for interface {interface.name or interface.id} on device {device.name}: {e}"
                    )

            # Config for loopback0 interface will be handled later
            if interface.name and interface.name.lower() == "loopback0":
                loopback0_interface = interface
                continue

            # Check if this is a VXLAN interface (name pattern: vxlan<VNI>)
            # Must check BEFORE virtual interface check since VXLAN interfaces have type=virtual
            interface_name = interface.label if interface.label else interface.name
            if interface_name and re.match(
                r"^vxlan\d+$", interface_name, re.IGNORECASE
            ):
                # Store VXLAN interface for later processing (needs loopback0 IP)
                vxlan_interfaces[interface_name] = interface
                logger.debug(
                    f"Found VXLAN interface {interface_name} on device {device.name}, will process after loopback0"
                )

                # Process VRF assignment
                if interface.id in interface_vrf_assignments:
                    vrf_name, vrf_table = interface_vrf_assignments[interface.id]
                    # Initialize VRF entry if not exists
                    if vrf_name not in network_vrfs:
                        network_vrfs[vrf_name] = {
                            "table": vrf_table,
                            "interfaces": [],
                        }
                    # Add VXLAN interface to VRF's interface list
                    if interface_name not in network_vrfs[vrf_name]["interfaces"]:
                        network_vrfs[vrf_name]["interfaces"].append(interface_name)
                        logger.debug(
                            f"Added VXLAN interface {interface_name} to VRF {vrf_name} (table {vrf_table}) for device {device.name}"
                        )
                continue

            # Check if this is a virtual interface (VLAN)
            if interface.type and interface.type.value == "virtual":
                # Check if interface has untagged VLAN and parent interface
                if hasattr(interface, "untagged_vlan") and interface.untagged_vlan:
                    if hasattr(interface, "parent") and interface.parent:
                        # Get full parent interface from bulk_loader to access all fields
                        # The nested parent object only has minimal fields (id, name, url)
                        parent_interface = self.bulk_loader.get_interface_by_id(
                            interface.parent.id
                        )
                        # Fall back to nested object if not found in bulk_loader
                        if not parent_interface:
                            parent_interface = interface.parent

                        # Check if parent interface also has managed-by-osism tag
                        parent_has_tag = False
                        if hasattr(parent_interface, "tags") and parent_interface.tags:
                            parent_tag_slugs = [
                                tag.slug for tag in parent_interface.tags
                            ]
                            parent_has_tag = "managed-by-osism" in parent_tag_slugs

                        # Only include VLAN if parent also has the tag
                        if not parent_has_tag:
                            continue

                        vlan_name = (
                            interface.label if interface.label else interface.name
                        )
                        if vlan_name:
                            # Use parent's label if available, otherwise name
                            parent_link = (
                                parent_interface.label
                                if hasattr(parent_interface, "label")
                                and parent_interface.label
                                else parent_interface.name
                            )
                            vlan_config = {
                                "id": interface.untagged_vlan.vid,
                                "link": parent_link,
                            }

                            # Use parent interface's MTU if available, otherwise use effective default
                            if (
                                hasattr(parent_interface, "mtu")
                                and parent_interface.mtu
                            ):
                                vlan_config["mtu"] = parent_interface.mtu
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

                            # Process VRF assignment if interface was successfully added
                            if interface.id in interface_vrf_assignments:
                                vrf_name, vrf_table = interface_vrf_assignments[
                                    interface.id
                                ]
                                # Initialize VRF entry if not exists
                                if vrf_name not in network_vrfs:
                                    network_vrfs[vrf_name] = {
                                        "table": vrf_table,
                                        "interfaces": [],
                                    }
                                # Add VLAN interface to VRF's interface list
                                if (
                                    vlan_name
                                    not in network_vrfs[vrf_name]["interfaces"]
                                ):
                                    network_vrfs[vrf_name]["interfaces"].append(
                                        vlan_name
                                    )
                                    logger.debug(
                                        f"Added VLAN interface {vlan_name} to VRF {vrf_name} (table {vrf_table}) for device {device.name}"
                                    )
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

            # Process VRF assignment if interface was successfully added
            if interface.id in interface_vrf_assignments:
                vrf_name, vrf_table = interface_vrf_assignments[interface.id]
                # Initialize VRF entry if not exists
                if vrf_name not in network_vrfs:
                    network_vrfs[vrf_name] = {
                        "table": vrf_table,
                        "interfaces": [],
                    }
                # Add ethernet interface to VRF's interface list
                if label not in network_vrfs[vrf_name]["interfaces"]:
                    network_vrfs[vrf_name]["interfaces"].append(label)
                    logger.debug(
                        f"Added ethernet interface {label} to VRF {vrf_name} (table {vrf_table}) for device {device.name}"
                    )

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

            # Add MTU - use interface MTU if set, otherwise use effective default
            if hasattr(loopback0_interface, "mtu") and loopback0_interface.mtu:
                loopback0_config["mtu"] = loopback0_interface.mtu
            else:
                loopback0_config["mtu"] = effective_default_mtu

            # Check for interface-specific netplan_parameters custom field
            if (
                hasattr(loopback0_interface, "custom_fields")
                and loopback0_interface.custom_fields
            ):
                interface_netplan_params = loopback0_interface.custom_fields.get(
                    "netplan_parameters"
                )
                if interface_netplan_params and isinstance(
                    interface_netplan_params, dict
                ):
                    # Merge interface-specific parameters into the loopback0 config
                    for key, value in interface_netplan_params.items():
                        if key == "addresses" and isinstance(value, list):
                            # Merge addresses lists (avoid duplicates)
                            if "addresses" in loopback0_config:
                                for addr in value:
                                    if addr not in loopback0_config["addresses"]:
                                        loopback0_config["addresses"].append(addr)
                            else:
                                loopback0_config["addresses"] = value
                        else:
                            # For all other keys, just update normally
                            loopback0_config[key] = value

            if loopback0_config:
                network_dummy_devices["loopback0"] = loopback0_config

        # Process VXLAN interfaces now that we have loopback0 information
        if vxlan_interfaces:
            # Extract loopback0 IPv4 address for VXLAN local address
            loopback0_ipv4 = None
            if loopback0_interface:
                try:
                    loopback0_ips = self.bulk_loader.get_interface_ip_addresses(
                        loopback0_interface
                    )
                    for ip in loopback0_ips:
                        if ip.address and "." in ip.address:  # IPv4
                            # Extract IP without prefix (e.g., "10.10.129.75/32" -> "10.10.129.75")
                            loopback0_ipv4 = ip.address.split("/")[0]
                            break
                except Exception as e:
                    logger.warning(
                        f"Failed to get loopback0 IP addresses for device {device.name}: {e}"
                    )

            for vxlan_name, vxlan_interface in vxlan_interfaces.items():
                # Extract VNI from interface name (e.g., "vxlan42" -> 42)
                vni_match = re.match(r"^vxlan(\d+)$", vxlan_name, re.IGNORECASE)
                if not vni_match:
                    logger.warning(
                        f"Could not extract VNI from VXLAN interface name {vxlan_name} on device {device.name}"
                    )
                    continue

                vni = int(vni_match.group(1))

                # Build tunnel configuration
                tunnel_config = {
                    "mode": "vxlan",
                    "link": "loopback0",
                    "id": vni,
                    "accept-ra": False,
                    "mac-learning": True,
                    "port": 4789,
                }

                # Set MTU - use interface MTU if available, otherwise use effective default
                if hasattr(vxlan_interface, "mtu") and vxlan_interface.mtu:
                    tunnel_config["mtu"] = vxlan_interface.mtu
                else:
                    tunnel_config["mtu"] = effective_default_mtu

                # Set local address from loopback0
                if loopback0_ipv4:
                    tunnel_config["local"] = loopback0_ipv4
                else:
                    logger.warning(
                        f"No loopback0 IPv4 address found for VXLAN {vxlan_name} on device {device.name}, 'local' will not be set"
                    )

                # Get IP addresses for this VXLAN interface (including VRF-assigned)
                addresses = []
                try:
                    ip_addresses = self.bulk_loader.get_interface_ip_addresses(
                        vxlan_interface
                    )
                    for ip in ip_addresses:
                        if ip.address:
                            addresses.append(ip.address)
                except Exception:
                    pass

                if addresses:
                    tunnel_config["addresses"] = addresses

                # Check for interface-specific netplan_parameters custom field
                if (
                    hasattr(vxlan_interface, "custom_fields")
                    and vxlan_interface.custom_fields
                ):
                    interface_netplan_params = vxlan_interface.custom_fields.get(
                        "netplan_parameters"
                    )
                    if interface_netplan_params and isinstance(
                        interface_netplan_params, dict
                    ):
                        # Merge interface-specific parameters into the tunnel config
                        tunnel_config.update(interface_netplan_params)

                network_tunnels[vxlan_name] = tunnel_config
                logger.debug(
                    f"Added VXLAN tunnel {vxlan_name} (VNI {vni}) for device {device.name}"
                )

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
        if (
            not network_ethernets
            and not network_dummy_devices
            and not network_vlans
            and not network_tunnels
        ):
            return None

        result = {}
        if network_ethernets:
            result["network_ethernets"] = network_ethernets
        if network_dummy_devices:
            result["network_dummy_devices"] = network_dummy_devices
        if network_vlans:
            result["network_vlans"] = network_vlans
        if network_tunnels:
            result["network_tunnels"] = network_tunnels
        if network_vrfs:
            result["network_vrfs"] = network_vrfs

        # Deep-merge overrides from local_context_data if available
        if hasattr(device, "local_context_data") and device.local_context_data:
            lcd_netplan = device.local_context_data.get("netplan_parameters")
            if lcd_netplan and isinstance(lcd_netplan, dict):
                logger.info(
                    f"Merging netplan_parameters from local_context_data for device {device.name}"
                )
                result = deep_merge(result, lcd_netplan)

        # Cache the generated parameters in the custom field
        if self.netbox_client:
            logger.info(
                f"Writing generated Netplan parameters for device {device.name}"
            )
            success = self.netbox_client.update_device_custom_field(
                device, "netplan_parameters", result
            )
            if not success:
                logger.warning(
                    f"Failed to cache Netplan parameters for device {device.name}"
                )

        return result
