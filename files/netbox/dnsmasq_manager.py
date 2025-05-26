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

            for device in all_devices:
                logger.debug(f"Collecting OOB interface for device {device}")

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
                    continue

                # Generate parameters if not cached
                ip_address, mac_address = netbox_client.get_device_oob_interface(device)

                if ip_address and mac_address:
                    # Format MAC address properly (lowercase with colons)
                    mac_formatted = mac_address.lower()
                    # Get inventory hostname for the device
                    device_hostname = get_inventory_hostname(device)
                    # Create dnsmasq DHCP host entry: "mac,hostname,ip"
                    host_entry = f"{mac_formatted},{device_hostname},{ip_address}"
                    all_dhcp_hosts.append(host_entry)
                    logger.debug(
                        f"Collected dnsmasq entry for {device_hostname}: {host_entry}"
                    )

                    # Prepare parameters for caching
                    cache_params = {
                        "dnsmasq_dhcp_hosts": [host_entry],
                        "dnsmasq_dhcp_macs": [],
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

            # Write collected entries to metalbox device(s)
            for device in devices:
                if (
                    device.role
                    and device.role.slug
                    and device.role.slug.lower() == "metalbox"
                ):
                    # Create the dnsmasq configuration data with all collected entries
                    dnsmasq_data = {
                        "dnsmasq_dhcp_hosts": all_dhcp_hosts,
                        "dnsmasq_dhcp_macs": all_dhcp_macs,
                    }

                    # Write to metalbox device's host vars
                    self._write_dnsmasq_to_device(device, dnsmasq_data)
                    logger.info(
                        f"Wrote {len(all_dhcp_hosts)} dnsmasq entries to metalbox device {device.name}"
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
            ip_address, mac_address = netbox_client.get_device_oob_interface(device)

            if ip_address and mac_address:
                # Format MAC address properly (lowercase with colons)
                mac_formatted = mac_address.lower()
                # Create dnsmasq DHCP host entry: "mac,hostname,ip"
                hostname = get_inventory_hostname(device)
                entry = f"{mac_formatted},{hostname},{ip_address}"
                logger.debug(f"Added dnsmasq entry for {hostname}: {entry}")

                # Create the dnsmasq configuration data
                dnsmasq_data = {f"dnsmasq_dhcp_hosts__{hostname}": [entry]}

                # Prepare parameters for caching
                cache_params = {"dnsmasq_dhcp_hosts": [entry], "dnsmasq_dhcp_macs": []}

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
        device_pattern = f"{device}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {device}, skipping dnsmasq writing"
            )
            return

        base_path = result[0] if len(result) == 1 else None

        # Write to device-specific file
        if base_path:
            if base_path.is_dir():
                output_file = base_path / "999-netbox-dnsmasq.yml"
                logger.debug(f"Writing dnsmasq config for {device} to {output_file}")
                with open(output_file, "w+", encoding="utf-8") as fp:
                    yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
            else:
                # For existing single file, append with separator
                logger.debug(f"Appending dnsmasq config for {device} to {base_path}")
                with open(base_path, "a", encoding="utf-8") as fp:
                    fp.write("\n# NetBox dnsmasq\n")
                    yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
        else:
            # Create new directory structure
            device_dir = self.config.inventory_path / "host_vars" / str(device)
            device_dir.mkdir(parents=True, exist_ok=True)
            output_file = device_dir / "999-netbox-dnsmasq.yml"
            logger.debug(f"Writing dnsmasq config for {device} to {output_file}")
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
