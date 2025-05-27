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
                                entry = f"metalbox,{ip_only},vlan{interface_info['interface_identifier']}"
                                dynamic_hosts.append(entry)
                                logger.debug(f"Created dynamic host entry: {entry}")
                                break  # Only use the first matching IP
                        except Exception as e:
                            logger.warning(f"Failed to process IP {ip_str}: {e}")

        return dynamic_hosts

    def get_dhcp_options_for_metalbox(
        self, device: Any, netbox_client: NetBoxClient
    ) -> List[str]:
        """Generate dnsmasq DHCP options for metalbox virtual interfaces.

        For each virtual interface with IP address and managed-by-osism tag,
        create a DHCP option entry.

        Args:
            device: NetBox device object (must have metalbox role)
            netbox_client: NetBox API client

        Returns:
            List of DHCP option entries in format "tag:vlanXXX,6,ip"
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
                        logger.debug(f"Created DHCP option entry: {option_entry}")
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
        flush_cache: bool = False,
    ) -> None:
        """Process devices in metalbox mode.

        Collects all dnsmasq entries from all devices and writes them to metalbox devices.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
            all_devices: List of all devices to collect OOB configs from
            flush_cache: Force regeneration of cached parameters
        """
        # Collect all dnsmasq entries from all devices
        all_dhcp_hosts = []
        all_dhcp_macs = []
        all_dnsmasq_interfaces = []

        for device in all_devices:
            logger.debug(f"Collecting OOB interface for device {device}")

            # Check if device has metalbox role
            is_metalbox = (
                device.role
                and device.role.slug
                and device.role.slug.lower() == "metalbox"
            )

            # Check if dnsmasq_parameters custom field exists and use it (unless cache flush is requested)
            cached_params = device.custom_fields.get("dnsmasq_parameters")
            if cached_params and isinstance(cached_params, dict) and not flush_cache:
                logger.info(f"Using cached dnsmasq parameters for device {device.name}")
                if (
                    "dnsmasq_dhcp_hosts" in cached_params
                    and cached_params["dnsmasq_dhcp_hosts"]
                ):
                    all_dhcp_hosts.extend(cached_params["dnsmasq_dhcp_hosts"])
                if (
                    "dnsmasq_dhcp_macs" in cached_params
                    and cached_params["dnsmasq_dhcp_macs"]
                ):
                    all_dhcp_macs.extend(cached_params["dnsmasq_dhcp_macs"])
                if (
                    "dnsmasq_interfaces" in cached_params
                    and cached_params["dnsmasq_interfaces"]
                    and is_metalbox
                ):
                    all_dnsmasq_interfaces.extend(cached_params["dnsmasq_interfaces"])
                continue

            # Generate parameters if not cached
            ip_address, mac_address, vlan_id = netbox_client.get_device_oob_interface(
                device
            )

            if ip_address and mac_address:
                # Generate DHCP host entry
                host_entry = self.dhcp_generator.generate_dhcp_host_entry(
                    device, ip_address, mac_address, vlan_id
                )
                all_dhcp_hosts.append(host_entry)
                logger.debug(f"Collected dnsmasq entry for {device.name}: {host_entry}")

                # Get virtual interfaces for this device (only for metalbox devices)
                device_interfaces = []
                if is_metalbox:
                    device_interfaces = (
                        self.interface_handler.get_virtual_interfaces_for_dnsmasq(
                            device, netbox_client
                        )
                    )
                    all_dnsmasq_interfaces.extend(device_interfaces)

                # Prepare parameters for caching
                cache_params = {
                    "dnsmasq_dhcp_hosts": [host_entry],
                    "dnsmasq_dhcp_macs": [],
                    "dnsmasq_interfaces": device_interfaces,
                }

                # Generate DHCP MAC entry
                mac_entry = self.dhcp_generator.generate_dhcp_mac_entry(
                    device, mac_address
                )
                if mac_entry:
                    all_dhcp_macs.append(mac_entry)
                    cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                    logger.debug(
                        f"Collected dnsmasq MAC entry for {device.name}: {mac_entry}"
                    )

                # Cache the generated parameters
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
                        all_dnsmasq_interfaces.extend(device_interfaces)
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

                # Create the dnsmasq configuration data with all collected entries
                dnsmasq_data = {
                    "dnsmasq_dhcp_hosts": all_dhcp_hosts,
                    "dnsmasq_dhcp_macs": all_dhcp_macs,
                    "dnsmasq_interfaces": all_dnsmasq_interfaces,
                    "dnsmasq_dynamic_hosts": dynamic_hosts,
                    "dnsmasq_dhcp_options": dhcp_options,
                }

                # Write to metalbox device's host vars
                self.write_dnsmasq_to_device(device, dnsmasq_data)
                logger.info(
                    f"Wrote {len(all_dhcp_hosts)} dnsmasq entries, {len(dynamic_hosts)} dynamic hosts and {len(dhcp_options)} DHCP options to metalbox device {device.name}"
                )
