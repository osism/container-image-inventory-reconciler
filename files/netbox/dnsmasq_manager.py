# SPDX-License-Identifier: Apache-2.0

"""DNS and DHCP configuration management."""

import ipaddress
from typing import Any, List

from loguru import logger
import yaml

from config import Config
from utils import get_inventory_hostname
from netbox_client import NetBoxClient


class DnsmasqManager:
    """Manages dnsmasq configuration for devices."""

    def __init__(self, config: Config):
        self.config = config

    def _get_virtual_interfaces_for_dnsmasq(
        self, device: Any, netbox_client: NetBoxClient
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

    def _get_dynamic_hosts_for_metalbox(
        self, device: Any, netbox_client: NetBoxClient
    ) -> List[str]:
        """Generate dnsmasq_dynamic_hosts entries for metalbox device.

        For each OOB network with managed-by-osism tag, find the corresponding
        VLAN interface on the metalbox device and create an entry.

        Args:
            device: NetBox device object (must have metalbox role)
            netbox_client: NetBox API client

        Returns:
            List of dynamic host entries in format "metalbox,network,ip"
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

        # Build a map of VLAN ID to interface IP addresses
        vlan_to_ips = {}
        for interface in interfaces:
            # Check if this is a virtual interface with untagged VLAN
            if (
                interface.type
                and interface.type.value == "virtual"
                and hasattr(interface, "untagged_vlan")
                and interface.untagged_vlan
            ):
                vlan_id = interface.untagged_vlan.id

                # Get IP addresses for this interface
                try:
                    ip_addresses = netbox_client.api.ipam.ip_addresses.filter(
                        interface_id=interface.id
                    )
                    for ip in ip_addresses:
                        if ip.address:
                            if vlan_id not in vlan_to_ips:
                                vlan_to_ips[vlan_id] = []
                            vlan_to_ips[vlan_id].append(ip.address)
                except Exception:
                    pass

        # Match OOB networks with VLAN interfaces
        for network in oob_networks:
            # Check if this network has an associated VLAN
            if hasattr(network, "vlan") and network.vlan:
                vlan_id = network.vlan.id

                # Check if we have an interface for this VLAN
                if vlan_id in vlan_to_ips:
                    # Find the IP that belongs to this network
                    network_obj = ipaddress.ip_network(network.prefix)
                    for ip_str in vlan_to_ips[vlan_id]:
                        try:
                            # Remove the prefix length from IP if present
                            ip_only = ip_str.split("/")[0]
                            ip_addr = ipaddress.ip_address(ip_only)

                            # Check if this IP belongs to the network
                            if ip_addr in network_obj:
                                # Create dynamic host entry
                                entry = f"metalbox,{network.prefix},{ip_only}"
                                dynamic_hosts.append(entry)
                                logger.debug(f"Created dynamic host entry: {entry}")
                                break  # Only use the first matching IP
                        except Exception as e:
                            logger.warning(f"Failed to process IP {ip_str}: {e}")

        return dynamic_hosts

    def _get_dhcp_options_for_metalbox(
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

    def write_dnsmasq_config(
        self,
        netbox_client: NetBoxClient,
        devices: List[Any],
        all_devices: List[Any] = None,
        flush_cache: bool = False,
    ) -> None:
        """Write dnsmasq DHCP configuration for devices with OOB management interfaces.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
            all_devices: List of all devices (used in metalbox mode to collect all OOB configs)
            flush_cache: Force regeneration of cached parameters
        """
        # In metalbox mode, collect all dnsmasq entries to write to metalbox device
        if self.config.reconciler_mode == "metalbox" and all_devices:
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
                if (
                    cached_params
                    and isinstance(cached_params, dict)
                    and not flush_cache
                ):
                    logger.info(
                        f"Using cached dnsmasq parameters for device {device.name}"
                    )
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
                        all_dnsmasq_interfaces.extend(
                            cached_params["dnsmasq_interfaces"]
                        )
                    continue

                # Generate parameters if not cached
                ip_address, mac_address, vlan_id = (
                    netbox_client.get_device_oob_interface(device)
                )

                if ip_address and mac_address:
                    # Format MAC address properly (lowercase with colons)
                    mac_formatted = mac_address.lower()
                    # Get inventory hostname for the device
                    device_hostname = get_inventory_hostname(device)
                    # Create dnsmasq DHCP host entry: "mac,hostname,ip[,set:vlanXXX]"
                    if vlan_id:
                        host_entry = f"{mac_formatted},{device_hostname},{ip_address},set:vlan{vlan_id}"
                    else:
                        host_entry = f"{mac_formatted},{device_hostname},{ip_address}"
                    all_dhcp_hosts.append(host_entry)
                    logger.debug(
                        f"Collected dnsmasq entry for {device_hostname}: {host_entry}"
                    )

                    # Get virtual interfaces for this device (only for metalbox devices)
                    device_interfaces = []
                    if is_metalbox:
                        device_interfaces = self._get_virtual_interfaces_for_dnsmasq(
                            device, netbox_client
                        )
                        all_dnsmasq_interfaces.extend(device_interfaces)

                    # Prepare parameters for caching
                    cache_params = {
                        "dnsmasq_dhcp_hosts": [host_entry],
                        "dnsmasq_dhcp_macs": [],
                        "dnsmasq_interfaces": device_interfaces,
                    }

                    # Add dnsmasq_dhcp_macs using custom field or device type slug
                    custom_dhcp_tag = device.custom_fields.get("dnsmasq_dhcp_tag")

                    if custom_dhcp_tag:
                        # Use custom field value if set
                        mac_entry = f"tag:{custom_dhcp_tag},{mac_formatted}"
                        all_dhcp_macs.append(mac_entry)
                        cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                        logger.debug(
                            f"Collected dnsmasq MAC entry for {device.name} using custom tag: {mac_entry}"
                        )
                    elif device.device_type and device.device_type.slug:
                        # Fallback to device type slug
                        device_type_slug = device.device_type.slug
                        # Format: dhcp-mac=tag:device-type-slug,mac-address
                        mac_entry = f"tag:{device_type_slug},{mac_formatted}"
                        all_dhcp_macs.append(mac_entry)
                        cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                        logger.debug(
                            f"Collected dnsmasq MAC entry for {device.name} using device type: {mac_entry}"
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
                        device_interfaces = self._get_virtual_interfaces_for_dnsmasq(
                            device, netbox_client
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
                    dynamic_hosts = self._get_dynamic_hosts_for_metalbox(
                        device, netbox_client
                    )

                    # Generate DHCP options for this metalbox device
                    dhcp_options = self._get_dhcp_options_for_metalbox(
                        device, netbox_client
                    )

                    # Create the dnsmasq configuration data with all collected entries
                    dnsmasq_data = {
                        "dnsmasq_dhcp_hosts": all_dhcp_hosts,
                        "dnsmasq_dhcp_macs": all_dhcp_macs,
                        "dnsmasq_interfaces": all_dnsmasq_interfaces,
                        "dnsmasq_dynamic_hosts": dynamic_hosts,
                        "dnsmasq_dhcp_options": dhcp_options,
                    }

                    # Write to metalbox device's host vars
                    self._write_dnsmasq_to_device(device, dnsmasq_data)
                    logger.info(
                        f"Wrote {len(all_dhcp_hosts)} dnsmasq entries, {len(dynamic_hosts)} dynamic hosts and {len(dhcp_options)} DHCP options to metalbox device {device.name}"
                    )
            return

        # Original behavior for manager mode
        for device in devices:
            logger.debug(f"Checking OOB interface for device {device}")

            # Check if dnsmasq_parameters custom field exists and use it (unless cache flush is requested)
            cached_params = device.custom_fields.get("dnsmasq_parameters")
            if cached_params and isinstance(cached_params, dict) and not flush_cache:
                logger.info(f"Using cached dnsmasq parameters for device {device.name}")
                # Extract the cached values
                if (
                    "dnsmasq_dhcp_hosts" in cached_params
                    and "dnsmasq_dhcp_macs" in cached_params
                ):
                    # Create the dnsmasq configuration data from cached values
                    dnsmasq_data = {}
                    if cached_params["dnsmasq_dhcp_hosts"]:
                        dnsmasq_data[f"dnsmasq_dhcp_hosts__{device.name}"] = (
                            cached_params["dnsmasq_dhcp_hosts"]
                        )
                    if cached_params["dnsmasq_dhcp_macs"]:
                        dnsmasq_data[f"dnsmasq_dhcp_macs__{device.name}"] = (
                            cached_params["dnsmasq_dhcp_macs"]
                        )

                    # Write to device-specific file
                    self._write_dnsmasq_to_device(device, dnsmasq_data)
                    continue

            # Generate parameters if not cached
            ip_address, mac_address, vlan_id = netbox_client.get_device_oob_interface(
                device
            )

            if ip_address and mac_address:
                # Format MAC address properly (lowercase with colons)
                mac_formatted = mac_address.lower()
                # Use inventory_hostname if set, otherwise use device name
                hostname = get_inventory_hostname(device)
                # Create dnsmasq DHCP host entry: "mac,hostname,ip"
                # Note: In manager mode, we don't add VLAN tags
                entry = f"{mac_formatted},{hostname},{ip_address}"
                logger.debug(f"Added dnsmasq entry for {hostname}: {entry}")

                # Create the dnsmasq configuration data
                dnsmasq_data = {f"dnsmasq_dhcp_hosts__{hostname}": [entry]}

                # Prepare parameters for caching
                cache_params = {
                    "dnsmasq_dhcp_hosts": [entry],
                    "dnsmasq_dhcp_macs": [],
                }

                # Add dnsmasq_dhcp_macs using custom field or device type slug
                custom_dhcp_tag = device.custom_fields.get("dnsmasq_dhcp_tag")

                if custom_dhcp_tag:
                    # Use custom field value if set
                    mac_entry = f"tag:{custom_dhcp_tag},{mac_formatted}"
                    dnsmasq_data[f"dnsmasq_dhcp_macs__{device.name}"] = [mac_entry]
                    cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                    logger.debug(
                        f"Added dnsmasq MAC entry for {device.name} using custom tag: {mac_entry}"
                    )
                elif device.device_type and device.device_type.slug:
                    # Fallback to device type slug
                    device_type_slug = device.device_type.slug
                    # Format: dhcp-mac=tag:device-type-slug,mac-address
                    mac_entry = f"tag:{device_type_slug},{mac_formatted}"
                    dnsmasq_data[f"dnsmasq_dhcp_macs__{device.name}"] = [mac_entry]
                    cache_params["dnsmasq_dhcp_macs"] = [mac_entry]
                    logger.debug(
                        f"Added dnsmasq MAC entry for {device.name} using device type: {mac_entry}"
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

                # Write to device-specific file
                self._write_dnsmasq_to_device(device, dnsmasq_data)

    def _write_dnsmasq_to_device(self, device: Any, dnsmasq_data: dict) -> None:
        """Write dnsmasq configuration data to device's host vars.

        Args:
            device: The NetBox device object
            dnsmasq_data: Dictionary containing dnsmasq configuration
        """
        # Determine base path for device files
        host_vars_path = self.config.inventory_path / "host_vars"
        # Use inventory_hostname if set, otherwise use device name
        hostname = get_inventory_hostname(device)
        device_pattern = f"{hostname}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {hostname}, skipping dnsmasq writing"
            )
            return

        base_path = result[0] if len(result) == 1 else None

        # Write to device-specific file
        if base_path:
            if base_path.is_dir():
                output_file = base_path / "999-netbox-dnsmasq.yml"
                logger.debug(f"Writing dnsmasq config for {hostname} to {output_file}")
                with open(output_file, "w+", encoding="utf-8") as fp:
                    yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
            else:
                # For existing single file, append with separator
                logger.debug(f"Appending dnsmasq config for {hostname} to {base_path}")
                with open(base_path, "a", encoding="utf-8") as fp:
                    fp.write("\n# NetBox dnsmasq\n")
                    yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
        else:
            # Create new directory structure
            device_dir = self.config.inventory_path / "host_vars" / hostname
            device_dir.mkdir(parents=True, exist_ok=True)
            output_file = device_dir / "999-netbox-dnsmasq.yml"
            logger.debug(f"Writing dnsmasq config for {hostname} to {output_file}")
            with open(output_file, "w+", encoding="utf-8") as fp:
                yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)

    def write_dnsmasq_dhcp_ranges(self, netbox_client: NetBoxClient) -> None:
        """Generate and write dnsmasq DHCP ranges for OOB networks."""
        oob_networks = netbox_client.get_oob_networks()

        if not oob_networks:
            logger.debug("No OOB networks with managed-by-osism tag found")
            return

        dhcp_ranges = []

        for network in oob_networks:
            try:
                # Parse the network prefix
                net = ipaddress.ip_network(network.prefix)

                # Get all hosts in the network (excluding network and broadcast addresses)
                all_hosts = list(net.hosts())

                if len(all_hosts) < 3:
                    logger.warning(
                        f"Network {network.prefix} has fewer than 3 usable hosts"
                    )
                    continue

                # Reserve first and last host addresses
                # Use the range from second host to second-to-last host
                start_ip = str(all_hosts[1])  # Skip first host
                end_ip = str(all_hosts[-2])  # Skip last host
                subnet_mask = str(net.netmask)

                # Add 'static' mode to only allow static assignments
                dhcp_range = f"{start_ip},{end_ip},{subnet_mask},static"
                dhcp_ranges.append(dhcp_range)

                logger.debug(
                    f"Generated DHCP range for {network.prefix}: {dhcp_range} "
                    f"(reserved: {all_hosts[0]} and {all_hosts[-1]})"
                )

            except Exception as e:
                logger.warning(f"Failed to process network {network.prefix}: {e}")
                continue

        if dhcp_ranges:
            # Write the dnsmasq DHCP ranges to group_vars/manager
            dnsmasq_dhcp_data = {"dnsmasq_dhcp_ranges": dhcp_ranges}

            # Ensure group_vars/manager directory exists
            group_vars_path = self.config.inventory_path / "group_vars" / "manager"
            group_vars_path.mkdir(parents=True, exist_ok=True)

            # Write to 999-netbox-dnsmasq-dhcp-range.yml
            output_file = group_vars_path / "999-netbox-dnsmasq-dhcp-range.yml"
            logger.debug(f"Writing DHCP ranges to {output_file}")

            with open(output_file, "w", encoding="utf-8") as fp:
                yaml.dump(
                    dnsmasq_dhcp_data, fp, Dumper=yaml.Dumper, default_flow_style=False
                )
