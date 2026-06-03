# SPDX-License-Identifier: Apache-2.0

"""Netplan parameters extractor."""

import re
from typing import Any, Dict, List, Optional

from loguru import logger

from bulk_loader import BulkDataLoader
from config import DEFAULT_FRR_SWITCH_ROLES, DEFAULT_METALBOX_IPV6
from utils import deep_merge
from .base_extractor import BaseExtractor


# Keys a bond member's netplan_parameters custom field must never override:
# the MAC-rename identity (match / set-name) and any L3 / link-local config -
# the bond interface, not its members, carries the IP configuration.
_MEMBER_PROTECTED_KEYS = frozenset(
    {"match", "set-name", "addresses", "dhcp4", "dhcp6", "link-local"}
)


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

    def _collect_addresses(self, interface: Any) -> List[str]:
        """Return all IP addresses (with prefix) assigned to an interface."""
        addresses: List[str] = []
        try:
            for ip in self.bulk_loader.get_interface_ip_addresses(interface):
                if ip.address:
                    addresses.append(ip.address)
        except Exception:
            pass
        return addresses

    def _resolve_mtu(self, interface: Any, effective_default_mtu: int) -> int:
        """Return the interface's MTU if set, otherwise the effective default."""
        if hasattr(interface, "mtu") and interface.mtu:
            return interface.mtu
        return effective_default_mtu

    def _get_netplan_parameters(self, interface: Any) -> Optional[Dict[str, Any]]:
        """Return the interface's netplan_parameters custom field, if a dict."""
        if not (hasattr(interface, "custom_fields") and interface.custom_fields):
            return None
        params = interface.custom_fields.get("netplan_parameters")
        if params and isinstance(params, dict):
            return params
        return None

    def _apply_netplan_overrides(
        self,
        config: Dict[str, Any],
        params: Dict[str, Any],
        *,
        protected: frozenset = frozenset(),
        context: str = "",
    ) -> None:
        """Shallow-merge custom-field overrides into config.

        Keys listed in ``protected`` are skipped and logged, so a custom field
        can neither break an interface's identity nor reintroduce config that
        the interface type must not carry.
        """
        for key, value in params.items():
            if key in protected:
                logger.warning(
                    f"Ignoring '{key}' in netplan_parameters override for {context}"
                )
                continue
            config[key] = value

    def _register_vrf_membership(
        self,
        interface_id: Any,
        member_name: str,
        interface_vrf_assignments: Dict[Any, Any],
        network_vrfs: Dict[str, Any],
        device_name: str,
    ) -> None:
        """Add ``member_name`` to its VRF's interface list when a VRF is set."""
        if interface_id not in interface_vrf_assignments:
            return
        vrf_name, vrf_table = interface_vrf_assignments[interface_id]
        vrf_entry = network_vrfs.setdefault(
            vrf_name, {"table": vrf_table, "interfaces": []}
        )
        if member_name not in vrf_entry["interfaces"]:
            vrf_entry["interfaces"].append(member_name)
            logger.debug(
                f"Added interface {member_name} to VRF {vrf_name} "
                f"(table {vrf_table}) for device {device_name}"
            )

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

        For LAG / bond / port channel interfaces (type=lag):
        - The LAG itself must have the "managed-by-osism" tag, be enabled and not
          mgmt_only, and have a label or name (same gates as every other type)
        - Generates a network_bonds entry; a member interface is included only if
          it points at the LAG via its "lag" field AND independently passes the
          tag, MAC+label, enabled and mgmt_only gates - ineligible members are
          dropped (and logged), and a LAG with no eligible members is skipped
        - Members are renamed via their MAC but carry no IPs/DHCP; the bond
          interface always holds the IP configuration (bonds never receive the
          leaf / unnumbered treatment - they are expected to be IP-carrying here)
        - Defaults to an LACP (802.3ad) bond; override the parameters per LAG via
          the netplan_parameters custom field (e.g. to switch to active-backup).
          The auto-detected "interfaces" membership is authoritative and cannot
          be overridden by the custom field

        If device.config_context contains a "netplan_parameters" key, its values
        are deep-merged into the auto-generated parameters. Since config_context
        includes all Config Context sources (segments, regions, sites, roles, tags)
        plus local_context_data, this allows defining segment-wide defaults
        that can be overridden per device.

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
        network_bonds = {}
        loopback0_interface = None

        # Track VXLAN interfaces for later processing (need loopback0 IP first)
        # Format: {interface_name: interface_object}
        vxlan_interfaces = {}

        # Track VRF dummy interfaces for later processing
        # Format: {interface_name: interface_object}
        vrf_dummy_interfaces = {}

        # Track VRF assignments during interface processing
        # Format: {interface_id: (vrf_name, vrf_table)}
        interface_vrf_assignments = {}

        # Track LAG / bond / port channel members per LAG interface id
        # Format: {lag_interface_id: [member_label, ...]}
        bond_members = {}

        # Identify LAG (bond / port channel) interfaces up front so that member
        # interfaces can be linked to them regardless of interface ordering. A LAG
        # is modelled as a NetBox interface of type "lag" carrying the
        # managed-by-osism tag - the same NetBox modelling that SONiC port channel
        # detection relies on.
        lag_interfaces_by_id = {}
        for interface in interfaces:
            if not (
                interface.type
                and interface.type.value == "lag"
                and getattr(interface, "tags", None)
                and "managed-by-osism" in [tag.slug for tag in interface.tags]
            ):
                continue

            # Apply the same eligibility gates the main loop uses for every
            # other interface type. A mgmt_only or disabled LAG must not be
            # emitted as an active bond, and a LAG with neither label nor name
            # cannot be addressed.
            if getattr(interface, "mgmt_only", False):
                logger.debug(
                    f"Skipping mgmt_only LAG {interface.name or interface.id} "
                    f"on device {device.name}"
                )
                continue
            if not getattr(interface, "enabled", True):
                logger.debug(
                    f"Skipping disabled LAG {interface.name or interface.id} "
                    f"on device {device.name}"
                )
                continue
            if not (interface.label or interface.name):
                continue

            lag_interfaces_by_id[interface.id] = interface

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
                self._register_vrf_membership(
                    interface.id,
                    interface_name,
                    interface_vrf_assignments,
                    network_vrfs,
                    device.name,
                )
                continue

            # LAG / bond / port channel interfaces are never emitted as
            # ethernets: eligible ones are processed in the dedicated post-loop
            # pass (members may appear before or after the LAG itself), and
            # ineligible ones (mgmt_only / disabled / nameless) are dropped here.
            if interface.type and interface.type.value == "lag":
                continue

            # Check if this is a virtual interface (VLAN or VRF dummy)
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
                            vlan_config["mtu"] = self._resolve_mtu(
                                interface.parent, effective_default_mtu
                            )

                            # Get IP addresses for this VLAN interface
                            addresses = self._collect_addresses(interface)
                            if addresses:
                                vlan_config["addresses"] = addresses

                            # Check for interface-specific netplan_parameters custom field
                            vlan_params = self._get_netplan_parameters(interface)
                            if vlan_params:
                                self._apply_netplan_overrides(vlan_config, vlan_params)

                            network_vlans[vlan_name] = vlan_config

                            # Process VRF assignment if interface was successfully added
                            self._register_vrf_membership(
                                interface.id,
                                vlan_name,
                                interface_vrf_assignments,
                                network_vrfs,
                                device.name,
                            )
                elif (
                    hasattr(interface, "vrf")
                    and interface.vrf
                    and hasattr(interface.vrf, "name")
                    and str(interface.vrf.name).lower().startswith("vrf")
                    and not interface.mac_address
                ):
                    # VRF dummy interface (e.g., lo-vrf-a, lo-vrf-b)
                    iface_name = interface.label if interface.label else interface.name
                    if iface_name:
                        vrf_dummy_interfaces[iface_name] = interface
                        logger.debug(
                            f"Found VRF dummy interface {iface_name} on device {device.name}"
                        )
                continue

            # Skip interfaces without MAC address or label
            if not interface.mac_address or not interface.label:
                continue

            # Use label as the interface name
            label = interface.label

            # Determine LAG membership up front so the disabled-interface and
            # custom-field handling below can be member-aware.
            lag_parent_id = (
                interface.lag.id if getattr(interface, "lag", None) else None
            )
            is_lag_member = (
                lag_parent_id is not None and lag_parent_id in lag_interfaces_by_id
            )

            interface_config = {
                "match": {"macaddress": interface.mac_address.lower()},
                "set-name": label,
            }

            # Check if interface is disabled
            is_enabled = getattr(interface, "enabled", True)
            if not is_enabled:
                if is_lag_member:
                    # A disabled member is dropped from the bond entirely.
                    # Emitting it as a standalone activation-mode: off ethernet
                    # would orphan it from the bond's interfaces list.
                    logger.debug(
                        f"Skipping disabled member {label} of LAG "
                        f"{lag_interfaces_by_id[lag_parent_id].name} "
                        f"on device {device.name}"
                    )
                    continue
                # For disabled interfaces, only set basic config and mark as down
                interface_config["activation-mode"] = "off"
                network_ethernets[label] = interface_config
                continue

            # Add MTU - use interface MTU if set, otherwise use effective default
            interface_config["mtu"] = self._resolve_mtu(
                interface, effective_default_mtu
            )

            # Bond / port channel members only need the MAC-based rename and the
            # MTU here. The bond interface itself carries the IP configuration, so
            # members must not get addresses, DHCP or leaf link-local settings -
            # a member's custom field cannot reintroduce those or break its
            # MAC-rename identity (see _MEMBER_PROTECTED_KEYS).
            if is_lag_member:
                member_params = self._get_netplan_parameters(interface)
                if member_params:
                    self._apply_netplan_overrides(
                        interface_config,
                        member_params,
                        protected=_MEMBER_PROTECTED_KEYS,
                        context=(
                            f"member {label} of LAG "
                            f"{lag_interfaces_by_id[lag_parent_id].name} "
                            f"on device {device.name}"
                        ),
                    )
                network_ethernets[label] = interface_config
                bond_members.setdefault(lag_parent_id, []).append(label)
                logger.debug(
                    f"Interface {label} is a member of LAG "
                    f"{lag_interfaces_by_id[lag_parent_id].name} on device {device.name}"
                )
                continue

            # Get IP addresses for this interface
            addresses = self._collect_addresses(interface)
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
            ethernet_params = self._get_netplan_parameters(interface)
            if ethernet_params:
                self._apply_netplan_overrides(interface_config, ethernet_params)

            network_ethernets[label] = interface_config

            # Process VRF assignment if interface was successfully added
            self._register_vrf_membership(
                interface.id,
                label,
                interface_vrf_assignments,
                network_vrfs,
                device.name,
            )

        # Add loopback0 configuration if found
        if loopback0_interface:
            loopback0_config = {}

            # Get all IP addresses assigned to loopback0 using bulk_loader
            addresses = self._collect_addresses(loopback0_interface)

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
            loopback0_config["mtu"] = self._resolve_mtu(
                loopback0_interface, effective_default_mtu
            )

            # Check for interface-specific netplan_parameters custom field. The
            # loopback0 merge is address-aware (it unions instead of replacing
            # addresses), so it does not use the shared override helper.
            interface_netplan_params = self._get_netplan_parameters(loopback0_interface)
            if interface_netplan_params:
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
                tunnel_config["mtu"] = self._resolve_mtu(
                    vxlan_interface, effective_default_mtu
                )

                # Set local address from loopback0
                if loopback0_ipv4:
                    tunnel_config["local"] = loopback0_ipv4
                else:
                    logger.warning(
                        f"No loopback0 IPv4 address found for VXLAN {vxlan_name} on device {device.name}, 'local' will not be set"
                    )

                # Get IP addresses for this VXLAN interface (including VRF-assigned)
                addresses = self._collect_addresses(vxlan_interface)
                if addresses:
                    tunnel_config["addresses"] = addresses

                # Check for interface-specific netplan_parameters custom field
                vxlan_params = self._get_netplan_parameters(vxlan_interface)
                if vxlan_params:
                    self._apply_netplan_overrides(tunnel_config, vxlan_params)

                network_tunnels[vxlan_name] = tunnel_config
                logger.debug(
                    f"Added VXLAN tunnel {vxlan_name} (VNI {vni}) for device {device.name}"
                )

        # Process VRF dummy interfaces
        for vrf_dummy_name, vrf_dummy_interface in vrf_dummy_interfaces.items():
            dummy_config = {}

            # Get IP addresses
            addresses = self._collect_addresses(vrf_dummy_interface)
            if addresses:
                dummy_config["addresses"] = addresses

            # Add MTU - use interface MTU if set, otherwise use effective default
            dummy_config["mtu"] = self._resolve_mtu(
                vrf_dummy_interface, effective_default_mtu
            )

            # Check for interface-specific netplan_parameters custom field
            dummy_params = self._get_netplan_parameters(vrf_dummy_interface)
            if dummy_params:
                self._apply_netplan_overrides(dummy_config, dummy_params)

            if dummy_config:
                network_dummy_devices[vrf_dummy_name] = dummy_config
                logger.debug(
                    f"Added VRF dummy interface {vrf_dummy_name} for device {device.name}"
                )

            # Process VRF assignment
            self._register_vrf_membership(
                vrf_dummy_interface.id,
                vrf_dummy_name,
                interface_vrf_assignments,
                network_vrfs,
                device.name,
            )

        # Process LAG / bond / port channel interfaces now that all members are
        # known. The default parameters configure an LACP (802.3ad) port channel;
        # they can be overridden per LAG via the netplan_parameters custom field on
        # the LAG interface (e.g. to switch to active-backup).
        for lag_id, lag_interface in lag_interfaces_by_id.items():
            bond_name = (
                lag_interface.label if lag_interface.label else lag_interface.name
            )
            if not bond_name:
                continue

            members = bond_members.get(lag_id, [])
            if not members:
                # A managed LAG whose members are all ineligible (untagged,
                # disabled, mgmt_only or missing MAC/label) would otherwise emit
                # an empty "interfaces" list, which is invalid netplan. Skip the
                # bond with a warning rather than emitting a broken entry.
                logger.warning(
                    f"Skipping bond {bond_name} on device {device.name}: "
                    f"no eligible member interfaces"
                )
                continue

            bond_config = {
                "interfaces": members,
                "parameters": {
                    "mode": "802.3ad",
                    "lacp-rate": "fast",
                    "mii-monitor-interval": 100,
                    "transmit-hash-policy": "layer3+4",
                },
            }

            # Add MTU - use interface MTU if set, otherwise use effective default
            bond_config["mtu"] = self._resolve_mtu(lag_interface, effective_default_mtu)

            # IP addresses are assigned to the LAG interface itself
            addresses = self._collect_addresses(lag_interface)
            if addresses:
                bond_config["addresses"] = addresses

            # Per-LAG override via the netplan_parameters custom field. A shallow
            # update mirrors the behaviour for other interface types: providing a
            # "parameters" dict replaces the auto-generated defaults entirely (so
            # e.g. an active-backup bond does not keep LACP-only options). The
            # auto-detected membership is authoritative, so an "interfaces"
            # override is rejected.
            lag_params = self._get_netplan_parameters(lag_interface)
            if lag_params:
                self._apply_netplan_overrides(
                    bond_config,
                    lag_params,
                    protected=frozenset({"interfaces"}),
                    context=f"bond {bond_name} on device {device.name}",
                )

            network_bonds[bond_name] = bond_config
            logger.debug(
                f"Added bond {bond_name} with members "
                f"{bond_config['interfaces']} for device {device.name}"
            )

            # Process VRF assignment for the LAG interface if present
            self._register_vrf_membership(
                lag_id,
                bond_name,
                interface_vrf_assignments,
                network_vrfs,
                device.name,
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
            and not network_bonds
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
        if network_bonds:
            result["network_bonds"] = network_bonds
        if network_vrfs:
            result["network_vrfs"] = network_vrfs

        # Deep-merge overrides from config_context if available
        # config_context includes merged data from all Config Context sources
        # (segments, regions, sites, roles, tags, etc.) plus local_context_data,
        # so segment-level netplan_parameters defaults are also applied.
        if hasattr(device, "config_context") and device.config_context:
            cc_netplan = device.config_context.get("netplan_parameters")
            if cc_netplan and isinstance(cc_netplan, dict):
                logger.info(
                    f"Merging netplan_parameters from config_context for device {device.name}"
                )
                result = deep_merge(result, cc_netplan)

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
