# SPDX-License-Identifier: Apache-2.0

"""Metalbox mode handler for dnsmasq configuration."""

import ipaddress
from typing import Any, List

from loguru import logger

from netbox_client import NetBoxClient
from .base import DnsmasqBase
from .dhcp_config import DHCPConfigGenerator
from .interface_handler import InterfaceHandler


class MetalboxModeHandler(DnsmasqBase):
    """Handles dnsmasq configuration for metalbox mode."""

    def __init__(self, config):
        super().__init__(config)
        self.dhcp_generator = DHCPConfigGenerator(config)
        self.interface_handler = InterfaceHandler()

    def get_dynamic_hosts_for_metalbox(
        self, device: Any, netbox_client: NetBoxClient
    ) -> List[str]:
        """Generate dnsmasq_dynamic_hosts entries for metalbox device.

        For each OOB network with managed-by-osism tag, find the corresponding
        VLAN interface on the metalbox device and create an entry.

        Args:
            device: NetBox device object (must have metalbox role)
            netbox_client: NetBox API client

        Returns:
            List of dynamic host entries in format "metalbox,ip,vlanVLAN_ID"
        """
        dynamic_hosts = []

        # Get OOB networks
        oob_networks = netbox_client.get_oob_networks()
        if not oob_networks:
            return dynamic_hosts

        # Get all interfaces for this device
        try:
            interfaces = netbox_client.api.dcim.interfaces.filter(device_id=device.id)
        except Exception as e:
            logger.warning(f"Failed to get interfaces for device {device.name}: {e}")
            return dynamic_hosts

        # Build a map of VLAN ID to interface label/name and IP addresses
        vlan_to_interface_info = {}
        for interface in interfaces:
            # Check if this is a virtual interface with untagged VLAN
            if (
                interface.type
                and interface.type.value == "virtual"
                and hasattr(interface, "untagged_vlan")
                and interface.untagged_vlan
            ):
                vlan_id = interface.untagged_vlan.vid
                # Use label if available, otherwise use name
                interface_identifier = (
                    interface.label if interface.label else interface.name
                )

                # Get IP addresses for this interface
                try:
                    ip_addresses = netbox_client.api.ipam.ip_addresses.filter(
                        interface_id=interface.id
                    )
                    for ip in ip_addresses:
                        if ip.address:
                            if vlan_id not in vlan_to_interface_info:
                                vlan_to_interface_info[vlan_id] = {
                                    "ips": [],
                                    "interface_identifier": interface_identifier,
                                }
                            vlan_to_interface_info[vlan_id]["ips"].append(ip.address)
                except Exception:
                    pass

        # Match OOB networks with VLAN interfaces
        for network in oob_networks:
            # Check if this network has an associated VLAN
            if hasattr(network, "vlan") and network.vlan:
                vlan_id = network.vlan.vid

                # Check if we have an interface for this VLAN
                if vlan_id in vlan_to_interface_info:
                    interface_info = vlan_to_interface_info[vlan_id]
                    # Find the IP that belongs to this network
                    network_obj = ipaddress.ip_network(network.prefix)
                    for ip_str in interface_info["ips"]:
                        try:
                            # Remove the prefix length from IP if present
                            ip_only = ip_str.split("/")[0]
                            ip_addr = ipaddress.ip_address(ip_only)

                            # Check if this IP belongs to the network
                            if ip_addr in network_obj:
                                # Create dynamic host entry using interface label/name
                                entry = f"metalbox,{ip_only},{interface_info['interface_identifier']}"
                                dynamic_hosts.append(entry)
                                logger.debug(f"Created dynamic host entry: {entry}")

                                # Also create entry for metalbox.osism.xyz with same IP and interface
                                osism_entry = f"metalbox.osism.xyz,{ip_only},{interface_info['interface_identifier']}"
                                dynamic_hosts.append(osism_entry)
                                logger.debug(
                                    f"Created dynamic host entry: {osism_entry}"
                                )
                                break  # Only use the first matching IP
                        except Exception as e:
                            logger.warning(f"Failed to process IP {ip_str}: {e}")

        return dynamic_hosts

    def get_dhcp_options_for_metalbox(
        self, device: Any, netbox_client: NetBoxClient
    ) -> List[str]:
        """Generate dnsmasq DHCP options for metalbox virtual interfaces.

        For each virtual interface with IP address and managed-by-osism tag,
        create a DHCP option entry. Additionally, the VLAN's associated prefix
        must also have the managed-by-osism tag.

        If the VLAN is in a VLAN group with name "routed", also add DHCP option 3 (Gateway).

        Args:
            device: NetBox device object (must have metalbox role)
            netbox_client: NetBox API client

        Returns:
            List of DHCP option entries in format "tag:vlanXXX,6,ip", "tag:vlanXXX,42,ip" and "tag:vlanXXX,3,ip"
        """
        dhcp_options = []

        # Get interfaces from device
        try:
            interfaces = netbox_client.api.dcim.interfaces.filter(device_id=device.id)
        except Exception as e:
            logger.warning(f"Failed to get interfaces for device {device.name}: {e}")
            return dhcp_options

        if not interfaces:
            return dhcp_options

        # Get all prefixes with managed-by-osism tag to check VLAN associations
        try:
            managed_prefixes = netbox_client.api.ipam.prefixes.filter(
                tag=["managed-by-osism"]
            )
            # Build a set of VLAN IDs that have managed prefixes
            managed_vlan_ids = set()
            for prefix in managed_prefixes:
                if hasattr(prefix, "vlan") and prefix.vlan:
                    managed_vlan_ids.add(prefix.vlan.vid)
        except Exception as e:
            logger.warning(f"Failed to get managed prefixes: {e}")
            # If we can't get prefixes, fall back to no filtering
            managed_vlan_ids = None

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

            vlan_id = interface.untagged_vlan.vid

            # Check if the VLAN's prefix has managed-by-osism tag
            if managed_vlan_ids is not None and vlan_id not in managed_vlan_ids:
                logger.debug(
                    f"Skipping interface {interface.name} - VLAN {vlan_id} prefix does not have managed-by-osism tag"
                )
                continue

            # Check if VLAN is in a routed VLAN group
            is_routed_vlan = False
            try:
                vlan_obj = interface.untagged_vlan
                if (
                    hasattr(vlan_obj, "group")
                    and vlan_obj.group
                    and hasattr(vlan_obj.group, "name")
                ):
                    if "routed" in vlan_obj.group.name.lower():
                        is_routed_vlan = True
                        logger.debug(f"VLAN {vlan_id} is in routed VLAN group")
            except Exception as e:
                logger.debug(f"Failed to check VLAN group for VLAN {vlan_id}: {e}")

            # Get IP addresses for this interface
            try:
                ip_addresses = netbox_client.api.ipam.ip_addresses.filter(
                    interface_id=interface.id
                )
                for ip in ip_addresses:
                    if ip.address:
                        # Extract IP without prefix
                        ip_only = ip.address.split("/")[0]
                        # Create DHCP option entry: tag:vlanXXX,6,ip
                        option_entry = f"tag:vlan{vlan_id},6,{ip_only}"
                        dhcp_options.append(option_entry)
                        logger.debug(f"Created DHCP DNS option entry: {option_entry}")

                        # Create DHCP option 42 entry: tag:vlanXXX,42,ip
                        ntp_option_entry = f"tag:vlan{vlan_id},42,{ip_only}"
                        dhcp_options.append(ntp_option_entry)
                        logger.debug(
                            f"Created DHCP NTP option entry: {ntp_option_entry}"
                        )

                        # If VLAN is in routed group, also add DHCP option 3 (Gateway)
                        if is_routed_vlan:
                            # Calculate gateway IP as first address of the network
                            try:
                                ip_with_prefix = ip.address
                                network = ipaddress.ip_network(
                                    ip_with_prefix, strict=False
                                )
                                # Use the first usable IP address as gateway (network address + 1)
                                gateway_ip = str(network.network_address + 1)
                                gateway_entry = f"tag:vlan{vlan_id},3,{gateway_ip}"
                                dhcp_options.append(gateway_entry)
                                logger.debug(
                                    f"Created DHCP gateway option entry: {gateway_entry} (network: {network})"
                                )
                            except Exception as gw_e:
                                logger.warning(
                                    f"Failed to calculate gateway for {ip.address}: {gw_e}"
                                )

                        # Only use the first IP address per interface
                        break
            except Exception as e:
                logger.warning(f"Failed to get IPs for interface {interface.name}: {e}")

        return dhcp_options

    def process_devices(
        self,
        netbox_client: NetBoxClient,
        devices: List[Any],
        all_devices: List[Any],
    ) -> None:
        """Process devices in metalbox mode.

        Collects all dnsmasq entries from all devices (including switches) and writes them to metalbox devices.
        In metalbox mode, switches with managed-by-metalbox tag are also included.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
            all_devices: List of all devices to collect OOB configs from (includes switches)
        """
        # Collect all dnsmasq entries from all devices using dictionaries for deduplication
        # Key format:
        # - dhcp_hosts: hostname (2nd field from "mac,hostname,ip[,set:vlanXXX]")
        # - dhcp_macs: MAC address (2nd field from "tag:tagname,mac")
        # - interfaces: interface name (the string itself)
        all_dhcp_hosts_dict = {}
        all_dhcp_macs_dict = {}
        all_dnsmasq_interfaces_dict = {}
        # Track switch-specific entries
        switch_dhcp_hosts_dict = {}
        switch_dhcp_macs_dict = {}
        # Track metalbox-specific entries
        metalbox_own_dhcp_hosts_dict = {}
        metalbox_own_dhcp_macs_dict = {}

        for device in all_devices:
            logger.debug(f"Collecting OOB interface for device {device}")

            # Check if device has metalbox role
            is_metalbox = (
                device.role
                and device.role.slug
                and device.role.slug.lower() == "metalbox"
            )

            # Check if this device is a switch
            is_switch = (
                device.role
                and device.role.slug
                and device.role.slug.lower() in self.config.dnsmasq_switch_roles
            )

            # Generate parameters from NetBox data
            ip_address, mac_address, vlan_id = netbox_client.get_device_oob_interface(
                device
            )

            if mac_address:
                # Prepare parameters for caching
                cache_params = {
                    "dnsmasq_dhcp_hosts": [],
                    "dnsmasq_dhcp_macs": [],
                    "dnsmasq_interfaces": [],
                }

                # Generate DHCP host entry only if we have both IP and MAC
                if ip_address:
                    host_entry = self.dhcp_generator.generate_dhcp_host_entry(
                        device, ip_address, mac_address, vlan_id
                    )
                    # Use hostname as key for deduplication
                    parts = host_entry.split(",")
                    if len(parts) >= 2:
                        hostname = parts[1]
                        all_dhcp_hosts_dict[hostname] = host_entry
                        cache_params["dnsmasq_dhcp_hosts"] = [host_entry]
                        # Track switch-specific entries when generating new parameters
                        if is_switch:
                            switch_dhcp_hosts_dict[hostname] = host_entry
                        # Track metalbox own parameters when generating new parameters
                        if is_metalbox:
                            metalbox_own_dhcp_hosts_dict[hostname] = host_entry
                    logger.debug(
                        f"Collected dnsmasq entry for {device.name}: {host_entry}"
                    )
                else:
                    logger.info(
                        f"Device {device.name} has MAC {mac_address} but no IP address - "
                        f"skipping dnsmasq_dhcp_hosts entry, will generate dnsmasq_dhcp_macs only"
                    )

                # Get virtual interfaces for this device (only for metalbox devices)
                device_interfaces = []
                if is_metalbox:
                    device_interfaces = (
                        self.interface_handler.get_virtual_interfaces_for_dnsmasq(
                            device, netbox_client
                        )
                    )
                    # Use interface name as key for deduplication
                    for interface in device_interfaces:
                        all_dnsmasq_interfaces_dict[interface] = interface
                    cache_params["dnsmasq_interfaces"] = device_interfaces

                # Generate DHCP MAC entry (always generated when MAC exists)
                mac_entry = self.dhcp_generator.generate_dhcp_mac_entry(
                    device, mac_address
                )
                if mac_entry:
                    # Use MAC address as key for deduplication
                    parts = mac_entry.split(",")
                    if len(parts) >= 2:
                        mac = parts[1]
                        all_dhcp_macs_dict[mac] = mac_entry
                        cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                        # Track switch-specific MAC entries when generating new parameters
                        if is_switch:
                            switch_dhcp_macs_dict[mac] = mac_entry
                        # Track metalbox own parameters when generating new parameters
                        if is_metalbox:
                            metalbox_own_dhcp_macs_dict[mac] = mac_entry
                    logger.debug(
                        f"Collected dnsmasq MAC entry for {device.name}: {mac_entry}"
                    )

                # Cache the generated parameters (even if only MAC entry exists)
                logger.info(
                    f"Caching generated dnsmasq parameters for device {device.name}"
                )
                success = netbox_client.update_device_custom_field(
                    device, "dnsmasq_parameters", cache_params
                )
                if not success:
                    logger.warning(
                        f"Failed to cache dnsmasq parameters for device {device.name}"
                    )
            else:
                # No OOB interface found, but still check for virtual interfaces (only for metalbox devices)
                if is_metalbox:
                    device_interfaces = (
                        self.interface_handler.get_virtual_interfaces_for_dnsmasq(
                            device, netbox_client
                        )
                    )
                    if device_interfaces:
                        # Use interface name as key for deduplication
                        for interface in device_interfaces:
                            all_dnsmasq_interfaces_dict[interface] = interface
                        # Cache just the interfaces
                        cache_params = {
                            "dnsmasq_dhcp_hosts": [],
                            "dnsmasq_dhcp_macs": [],
                            "dnsmasq_interfaces": device_interfaces,
                        }
                        logger.info(
                            f"Caching dnsmasq interfaces for metalbox device {device.name}"
                        )
                        netbox_client.update_device_custom_field(
                            device, "dnsmasq_parameters", cache_params
                        )

        # Write collected entries to metalbox device(s)
        for device in devices:
            if (
                device.role
                and device.role.slug
                and device.role.slug.lower() == "metalbox"
            ):
                # Generate dynamic hosts for this metalbox device
                dynamic_hosts = self.get_dynamic_hosts_for_metalbox(
                    device, netbox_client
                )

                # Generate DHCP options for this metalbox device
                dhcp_options = self.get_dhcp_options_for_metalbox(device, netbox_client)

                # Convert dictionaries to lists for writing
                all_dhcp_hosts = list(all_dhcp_hosts_dict.values())
                all_dhcp_macs = list(all_dhcp_macs_dict.values())
                all_dnsmasq_interfaces = list(all_dnsmasq_interfaces_dict.values())

                # Create the dnsmasq configuration data with all collected entries
                dnsmasq_data = {
                    "dnsmasq_dhcp_hosts__metalbox": all_dhcp_hosts,
                    "dnsmasq_dhcp_macs__metalbox": all_dhcp_macs,
                    "dnsmasq_interfaces__metalbox": all_dnsmasq_interfaces,
                    "dnsmasq_dynamic_hosts__metalbox": dynamic_hosts,
                    "dnsmasq_dhcp_options__metalbox": dhcp_options,
                }

                # Use only switch parameters (discard metalbox own parameters)
                switch_dhcp_hosts = list(switch_dhcp_hosts_dict.values())
                switch_dhcp_macs = list(switch_dhcp_macs_dict.values())

                # Store switch-only parameters in metalbox custom field
                if switch_dhcp_hosts or switch_dhcp_macs:
                    metalbox_cache_params = {
                        "dnsmasq_dhcp_hosts": switch_dhcp_hosts,
                        "dnsmasq_dhcp_macs": switch_dhcp_macs,
                        "dnsmasq_interfaces": all_dnsmasq_interfaces,  # Preserve metalbox VLAN interfaces
                    }

                    logger.info(
                        f"Caching {len(switch_dhcp_hosts_dict)} switch dnsmasq_dhcp_hosts and "
                        f"{len(switch_dhcp_macs_dict)} switch dnsmasq_dhcp_macs "
                        f"to metalbox device {device.name} (metalbox own parameters excluded)"
                    )

                    success = netbox_client.update_device_custom_field(
                        device, "dnsmasq_parameters", metalbox_cache_params
                    )

                    if not success:
                        logger.warning(
                            f"Failed to cache switch dnsmasq parameters for metalbox device {device.name}"
                        )

                # Write to metalbox device's host vars
                self.write_dnsmasq_to_device(device, dnsmasq_data)
                logger.info(
                    f"Wrote {len(all_dhcp_hosts)} dnsmasq entries, {len(dynamic_hosts)} dynamic hosts and {len(dhcp_options)} DHCP options to metalbox device {device.name}"
                )
