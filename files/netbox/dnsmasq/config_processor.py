# SPDX-License-Identifier: Apache-2.0

"""Configuration processor for dnsmasq special parameters."""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from loguru import logger

from netbox_client import NetBoxClient


class DnsmasqConfigProcessor:
    """Processes special dnsmasq configuration parameters."""

    def __init__(
        self,
        config_path: str = "/opt/configuration/environments/infrastructure/configuration.yml",
    ):
        self.config_path = Path(config_path)

    def load_configuration(self) -> Optional[Dict[str, Any]]:
        """Load configuration from YAML file.

        Returns:
            Dictionary with configuration data or None if file not found/invalid
        """
        try:
            if not self.config_path.exists():
                logger.debug(f"Configuration file {self.config_path} not found")
                return None

            with open(self.config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                logger.debug(f"Loaded configuration from {self.config_path}")
                return config
        except Exception as e:
            logger.warning(f"Failed to load configuration from {self.config_path}: {e}")
            return None

    def get_vlan_metalbox_mapping(self, netbox_client: NetBoxClient) -> Dict[int, str]:
        """Get mapping of VLAN ID to metalbox IP address.

        Args:
            netbox_client: NetBox API client

        Returns:
            Dictionary mapping VLAN ID to metalbox IP address
        """
        vlan_metalbox_map = {}

        try:
            # Get all devices with metalbox role
            metalbox_devices = netbox_client.api.dcim.devices.filter(role="metalbox")

            for device in metalbox_devices:
                logger.debug(f"Processing metalbox device: {device.name}")

                # Get interfaces for this metalbox device
                interfaces = netbox_client.api.dcim.interfaces.filter(
                    device_id=device.id
                )

                for interface in interfaces:
                    # Check if this is a virtual interface with untagged VLAN
                    if (
                        interface.type
                        and interface.type.value == "virtual"
                        and hasattr(interface, "untagged_vlan")
                        and interface.untagged_vlan
                    ):

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
                                    vlan_metalbox_map[vlan_id] = ip_only
                                    logger.debug(
                                        f"Mapped VLAN {vlan_id} to metalbox IP {ip_only}"
                                    )
                                    break  # Only use the first IP per interface
                        except Exception as e:
                            logger.warning(
                                f"Failed to get IPs for interface {interface.name}: {e}"
                            )

        except Exception as e:
            logger.warning(f"Failed to get metalbox devices: {e}")

        return vlan_metalbox_map

    def process_dhcp_parameters(
        self,
        original_entries: List[str],
        vlan_metalbox_map: Dict[int, str],
        parameter_type: str,
    ) -> List[str]:
        """Process dnsmasq DHCP parameters to create VLAN-specific entries.

        Args:
            original_entries: List of original parameter entries
            vlan_metalbox_map: Mapping of VLAN ID to metalbox IP
            parameter_type: Type of parameter ('options' or 'boot')

        Returns:
            List of processed entries with VLAN tags and metalbox IP replacements
        """
        processed_entries = []

        for entry in original_entries:
            logger.debug(f"Processing {parameter_type} entry: {entry}")

            # Create an entry for each available VLAN
            for vlan_id, metalbox_ip in vlan_metalbox_map.items():
                # Replace 'metalbox' with actual IP
                processed_entry = entry.replace("metalbox", metalbox_ip)

                # Add VLAN tag to the entry
                vlan_tag = f"tag:vlan{vlan_id}"

                # Insert VLAN tag after existing tags
                parts = processed_entry.split(",")

                # Find where to insert the VLAN tag
                # Look for existing tags at the beginning
                insert_pos = 0
                for i, part in enumerate(parts):
                    if part.startswith("tag:") or part.startswith("!tag:"):
                        insert_pos = i + 1
                    else:
                        break

                # Insert VLAN tag
                parts.insert(insert_pos, vlan_tag)
                final_entry = ",".join(parts)

                processed_entries.append(final_entry)
                logger.debug(
                    f"Created {parameter_type} entry for VLAN {vlan_id}: {final_entry}"
                )

        return processed_entries

    def process_special_parameters(
        self, netbox_client: NetBoxClient
    ) -> Dict[str, List[str]]:
        """Process special dnsmasq parameters from configuration file.

        Args:
            netbox_client: NetBox API client

        Returns:
            Dictionary with processed dnsmasq_dhcp_options and dnsmasq_dhcp_boot
        """
        result = {}

        # Load configuration
        config = self.load_configuration()
        if not config:
            return result

        # Check if dnsmasq_mode is set to 'metalbox'
        dnsmasq_mode = config.get("dnsmasq_mode")
        if dnsmasq_mode != "metalbox":
            logger.debug(
                f"dnsmasq_mode is '{dnsmasq_mode}', not 'metalbox'. Skipping special parameter processing"
            )
            return result

        logger.info("dnsmasq_mode is set to 'metalbox', processing special parameters")

        # Get VLAN to metalbox IP mapping
        vlan_metalbox_map = self.get_vlan_metalbox_mapping(netbox_client)
        if not vlan_metalbox_map:
            logger.warning(
                "No VLAN-metalbox mappings found, skipping special parameter processing"
            )
            return result

        logger.info(f"Found {len(vlan_metalbox_map)} VLAN-metalbox mappings")

        # Process dnsmasq_dhcp_options
        if "dnsmasq_dhcp_options" in config:
            original_options = config["dnsmasq_dhcp_options"]
            if isinstance(original_options, list):
                processed_options = self.process_dhcp_parameters(
                    original_options, vlan_metalbox_map, "options"
                )
                result["dnsmasq_dhcp_options"] = processed_options
                logger.info(
                    f"Processed {len(original_options)} dhcp_options into {len(processed_options)} VLAN-specific entries"
                )

        # Process dnsmasq_dhcp_boot
        if "dnsmasq_dhcp_boot" in config:
            original_boot = config["dnsmasq_dhcp_boot"]
            if isinstance(original_boot, list):
                processed_boot = self.process_dhcp_parameters(
                    original_boot, vlan_metalbox_map, "boot"
                )
                result["dnsmasq_dhcp_boot"] = processed_boot
                logger.info(
                    f"Processed {len(original_boot)} dhcp_boot into {len(processed_boot)} VLAN-specific entries"
                )

        return result
