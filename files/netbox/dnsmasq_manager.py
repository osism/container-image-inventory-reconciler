# SPDX-License-Identifier: Apache-2.0

"""DNS and DHCP configuration management."""

import ipaddress
from typing import Any, List

from loguru import logger
import yaml

from config import Config
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
    ) -> None:
        """Write dnsmasq DHCP configuration for devices with OOB management interfaces.

        Args:
            netbox_client: NetBox API client
            devices: List of devices to write configurations for
            all_devices: List of all devices (used in metalbox mode to collect all OOB configs)
        """
        # In metalbox mode, collect all dnsmasq entries to write to metalbox device
        if self.config.reconciler_mode == "metalbox" and all_devices:
            # Collect all dnsmasq entries from all devices
            all_dhcp_hosts = []
            all_dhcp_macs = []

            for device in all_devices:
                logger.debug(f"Collecting OOB interface for device {device}")
                ip_address, mac_address = netbox_client.get_device_oob_interface(device)

                if ip_address and mac_address:
                    # Format MAC address properly (lowercase with colons)
                    mac_formatted = mac_address.lower()
                    # Create dnsmasq DHCP host entry: "mac,hostname,ip"
                    host_entry = f"{mac_formatted},{device.name},{ip_address}"
                    all_dhcp_hosts.append(host_entry)
                    logger.debug(
                        f"Collected dnsmasq entry for {device.name}: {host_entry}"
                    )

                    # Add dnsmasq_dhcp_macs using custom field or device type slug
                    custom_dhcp_tag = device.custom_fields.get("dnsmasq_dhcp_tag")

                    if custom_dhcp_tag:
                        # Use custom field value if set
                        mac_entry = f"tag:{custom_dhcp_tag},{mac_formatted}"
                        all_dhcp_macs.append(mac_entry)
                        logger.debug(
                            f"Collected dnsmasq MAC entry for {device.name} using custom tag: {mac_entry}"
                        )
                    elif device.device_type and device.device_type.slug:
                        # Fallback to device type slug
                        device_type_slug = device.device_type.slug
                        # Format: dhcp-mac=tag:device-type-slug,mac-address
                        mac_entry = f"tag:{device_type_slug},{mac_formatted}"
                        all_dhcp_macs.append(mac_entry)
                        logger.debug(
                            f"Collected dnsmasq MAC entry for {device.name} using device type: {mac_entry}"
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
            ip_address, mac_address = netbox_client.get_device_oob_interface(device)

            if ip_address and mac_address:
                # Format MAC address properly (lowercase with colons)
                mac_formatted = mac_address.lower()
                # Create dnsmasq DHCP host entry: "mac,hostname,ip"
                entry = f"{mac_formatted},{device.name},{ip_address}"
                logger.debug(f"Added dnsmasq entry for {device.name}: {entry}")

                # Create the dnsmasq configuration data
                dnsmasq_data = {f"dnsmasq_dhcp_hosts__{device.name}": [entry]}

                # Add dnsmasq_dhcp_macs using custom field or device type slug
                custom_dhcp_tag = device.custom_fields.get("dnsmasq_dhcp_tag")

                if custom_dhcp_tag:
                    # Use custom field value if set
                    mac_entry = f"tag:{custom_dhcp_tag},{mac_formatted}"
                    dnsmasq_data[f"dnsmasq_dhcp_macs__{device.name}"] = [mac_entry]
                    logger.debug(
                        f"Added dnsmasq MAC entry for {device.name} using custom tag: {mac_entry}"
                    )
                elif device.device_type and device.device_type.slug:
                    # Fallback to device type slug
                    device_type_slug = device.device_type.slug
                    # Format: dhcp-mac=tag:device-type-slug,mac-address
                    mac_entry = f"tag:{device_type_slug},{mac_formatted}"
                    dnsmasq_data[f"dnsmasq_dhcp_macs__{device.name}"] = [mac_entry]
                    logger.debug(
                        f"Added dnsmasq MAC entry for {device.name} using device type: {mac_entry}"
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

                # Get all hosts in the network
                all_hosts = list(net.hosts())

                if len(all_hosts) < 4:
                    logger.warning(f"Network {network.prefix} has fewer than 4 hosts")
                    continue

                # Get the last 4 IP addresses
                last_4_hosts = all_hosts[-4:]

                # Create the DHCP range string
                # Format: start_ip,end_ip,subnet_mask,lease_time
                start_ip = str(last_4_hosts[0])
                end_ip = str(last_4_hosts[-1])
                subnet_mask = str(net.netmask)
                lease_time = "3h"  # 3 hours as specified

                dhcp_range = f"{start_ip},{end_ip},{subnet_mask},{lease_time}"
                dhcp_ranges.append(dhcp_range)

                logger.debug(f"Generated DHCP range for {network.prefix}: {dhcp_range}")

            except Exception as e:
                logger.warning(f"Failed to process network {network.prefix}: {e}")
                continue

        if dhcp_ranges:
            # Write the dnsmasq DHCP ranges to group_vars/all
            dnsmasq_dhcp_data = {"dnsmasq_dhcp_ranges": dhcp_ranges}

            # Ensure group_vars/all directory exists
            group_vars_path = self.config.inventory_path / "group_vars" / "all"
            group_vars_path.mkdir(parents=True, exist_ok=True)

            # Write to dnsmasq.yml
            output_file = group_vars_path / "dnsmasq.yml"
            logger.debug(f"Writing DHCP ranges to {output_file}")

            with open(output_file, "w", encoding="utf-8") as fp:
                yaml.dump(
                    dnsmasq_dhcp_data, fp, Dumper=yaml.Dumper, default_flow_style=False
                )
