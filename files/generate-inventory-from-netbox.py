# SPDX-License-Identifier: Apache-2.0

"""NetBox inventory generator for OSISM.

This script reads all required systems from the NetBox and writes them
into a form that can be evaluated by the Ansible Inventory Plugin INI.

This is a workaround to use the groups defined in cfg-generics without
having to import them into NetBox.
"""

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import ipaddress

import jinja2
from loguru import logger
import pynetbox
import yaml


@dataclass
class Config:
    """Configuration settings for NetBox integration."""

    netbox_url: str
    netbox_token: str
    ignore_ssl_errors: bool = True
    retry_attempts: int = 10
    retry_delay: int = 1
    inventory_path: Path = Path("/inventory.pre")
    template_path: Path = Path("/templates/")
    data_types: List[str] = None  # Configurable data types to extract
    ignored_roles: List[str] = None  # Device roles to ignore

    @classmethod
    def from_environment(cls) -> "Config":
        """Create configuration from environment variables."""
        netbox_url = os.getenv("NETBOX_API")
        if not netbox_url:
            raise ValueError("NETBOX_API environment variable is required")

        netbox_token = os.getenv("NETBOX_TOKEN", cls._read_secret("NETBOX_TOKEN"))
        if not netbox_token:
            raise ValueError("NETBOX_TOKEN not found in environment or secrets")

        # Parse data types from environment variable (comma-separated)
        data_types_env = os.getenv("NETBOX_DATA_TYPES", "")
        data_types = None
        if data_types_env:
            data_types = [dt.strip() for dt in data_types_env.split(",") if dt.strip()]

        # Parse ignored roles from environment variable (comma-separated)
        # Default: skip 'housing', 'pdu', 'other' and 'oob' roles
        ignored_roles_env = os.getenv("NETBOX_IGNORED_ROLES", "housing,pdu,other,oob")
        ignored_roles = [
            role.strip().lower()
            for role in ignored_roles_env.split(",")
            if role.strip()
        ]

        return cls(
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            ignore_ssl_errors=os.getenv("IGNORE_SSL_ERRORS", "True") == "True",
            inventory_path=Path(os.getenv("INVENTORY_PATH", "/inventory.pre")),
            template_path=Path(os.getenv("TEMPLATE_PATH", "/templates/")),
            data_types=data_types,
            ignored_roles=ignored_roles,
        )

    @staticmethod
    def _read_secret(secret_name: str) -> str:
        """Read secret from file."""
        secret_path = Path(f"/run/secrets/{secret_name}")
        try:
            return secret_path.read_text(encoding="utf-8").strip()
        except (EnvironmentError, FileNotFoundError):
            return ""


class NetBoxClient:
    """Client for NetBox API operations."""

    def __init__(self, config: Config):
        self.config = config
        self.api = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection to NetBox with retry logic."""
        logger.info(f"Connecting to NetBox {self.config.netbox_url}")

        for attempt in range(self.config.retry_attempts):
            try:
                self.api = pynetbox.api(
                    self.config.netbox_url, self.config.netbox_token
                )

                if self.config.ignore_ssl_errors:
                    self._configure_ssl_ignore()

                # Test connection
                self.api.dcim.sites.count()
                logger.debug("Successfully connected to NetBox")
                return

            except Exception as e:
                logger.warning(f"NetBox connection attempt {attempt + 1} failed: {e}")
                time.sleep(self.config.retry_delay)

        raise ConnectionError("Failed to connect to NetBox after all retry attempts")

    def _configure_ssl_ignore(self) -> None:
        """Configure SSL certificate verification ignoring."""
        import requests

        requests.packages.urllib3.disable_warnings()
        session = requests.Session()
        session.verify = False
        self.api.http_session = session

    def get_managed_devices(self) -> Tuple[List[Any], List[Any]]:
        """Retrieve managed devices from NetBox.

        Returns:
            A tuple containing:
            - Devices with both managed-by-osism and managed-by-ironic tags
            - Devices with only managed-by-osism tag (not managed-by-ironic)
        """
        # First set: Nodes with both managed-by-osism AND managed-by-ironic
        devices_with_both_tags = self.api.dcim.devices.filter(
            tag=["managed-by-osism", "managed-by-ironic"],
            status="active",
            cf_provision_state=["active"],
        )
        # Filter out devices where cf_maintenance is True
        devices_with_both_tags_filtered = [
            device
            for device in devices_with_both_tags
            if device.custom_fields.get("maintenance") is not True
        ]

        # Second set: Nodes with managed-by-osism but NOT managed-by-ironic
        # For these, cf_provision_state is not evaluated
        devices_osism_only = self.api.dcim.devices.filter(
            tag=["managed-by-osism"],
            status="active",
        )
        # Filter out devices that also have managed-by-ironic tag and where cf_maintenance is True
        devices_osism_only_filtered = [
            device
            for device in devices_osism_only
            if "managed-by-ironic" not in [tag.slug for tag in device.tags]
            and device.custom_fields.get("maintenance") is not True
        ]

        return devices_with_both_tags_filtered, devices_osism_only_filtered

    def get_device_oob_interface(
        self, device: Any
    ) -> Tuple[Optional[str], Optional[str]]:
        """Get OOB management interface with IP and MAC address for a device.

        Returns:
            A tuple of (ip_address, mac_address) or (None, None) if not found.
        """
        try:
            # Get all interfaces for the device
            interfaces = self.api.dcim.interfaces.filter(device_id=device.id)

            for interface in interfaces:
                # Check if interface has 'managed-by-osism' tag and is management only
                if not interface.tags or not interface.mgmt_only:
                    continue

                has_managed_tag = any(
                    tag.slug == "managed-by-osism" for tag in interface.tags
                )
                if not has_managed_tag:
                    continue

                # Get MAC address
                mac_address = interface.mac_address
                if not mac_address:
                    continue

                # Get IP addresses for this interface
                ip_addresses = self.api.ipam.ip_addresses.filter(
                    interface_id=interface.id
                )

                for ip in ip_addresses:
                    # Return the first IP address found
                    ip_without_mask = ip.address.split("/")[0]
                    return ip_without_mask, mac_address

            return None, None

        except Exception as e:
            logger.warning(f"Failed to get OOB interface for device {device}: {e}")
            return None, None

    def get_oob_networks(self) -> List[Any]:
        """Get networks with managed-by-osism tag and OOB role.

        Returns:
            List of prefix objects that have managed-by-osism tag and OOB role.
        """
        try:
            # Get all prefixes with managed-by-osism tag and OOB role
            prefixes = self.api.ipam.prefixes.filter(
                tag=["managed-by-osism"], role="oob"
            )
            return list(prefixes)
        except Exception as e:
            logger.warning(f"Failed to get OOB networks: {e}")
            return []


class DeviceDataExtractor:
    """Extracts various data fields from NetBox devices."""

    @staticmethod
    def extract_config_context(device: Any) -> Dict[str, Any]:
        """Extract config context from device."""
        return device.config_context

    @staticmethod
    def extract_custom_field(device: Any, field_name: str) -> Any:
        """Extract a specific custom field from device."""
        custom_fields = device.custom_fields or {}
        return custom_fields.get(field_name)

    @staticmethod
    def extract_primary_ip(device: Any) -> Optional[str]:
        """Extract primary IP address from device."""
        if device.primary_ip:
            return device.primary_ip.address.split("/")[0]
        return None

    @staticmethod
    def extract_all_data(device: Any) -> Dict[str, Any]:
        """Extract all configured data types from a device."""
        return {
            "config_context": DeviceDataExtractor.extract_config_context(device),
            "primary_ip": DeviceDataExtractor.extract_primary_ip(device),
            "netplan_parameters": DeviceDataExtractor.extract_custom_field(
                device, "netplan_parameters"
            ),
            "frr_parameters": DeviceDataExtractor.extract_custom_field(
                device, "frr_parameters"
            ),
        }


class InventoryManager:
    """Manages inventory file operations."""

    def __init__(self, config: Config):
        self.config = config
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath=str(config.template_path))
        )

    def write_device_data(self, device: Any, data_types: List[str] = None) -> None:
        """Write various device data types to appropriate files.

        Args:
            device: The NetBox device object
            data_types: List of data types to extract and write.
                       If None, only config_context will be used.
        """
        if data_types is None:
            data_types = ["config_context", "primary_ip"]

        # Extract all requested data
        all_data = DeviceDataExtractor.extract_all_data(device)

        # Determine base path for device files
        host_vars_path = self.config.inventory_path / "host_vars"
        device_pattern = f"{device}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {device}, skipping data writing"
            )
            return

        base_path = result[0] if len(result) == 1 else None

        # Write each data type to its own file
        for data_type in data_types:
            if data_type not in all_data:
                logger.warning(f"Unknown data type '{data_type}' for device {device}")
                continue

            data = all_data[data_type]
            if data is None or (isinstance(data, dict) and not data):
                logger.debug(f"No {data_type} data for device {device}, skipping")
                continue

            self._write_data_to_file(device, data_type, data, base_path)

    def _write_data_to_file(
        self, device: Any, data_type: str, data: Any, base_path: Optional[Path]
    ) -> None:
        """Write specific data type to file."""
        # Prepare content based on data type
        if data_type == "primary_ip":
            content = f"ansible_host: {data}\n"
        elif data_type in ["netplan_parameters", "frr_parameters"]:
            content = yaml.dump({data_type: data}, Dumper=yaml.Dumper)
        else:
            content = yaml.dump(data, Dumper=yaml.Dumper)

        # Determine file naming convention based on data type
        file_suffixes = {
            "config_context": "999-netbox-config-context.yml",
            "primary_ip": "999-netbox-ansible.yml",
            "netplan_parameters": "999-netbox-netplan.yml",
            "frr_parameters": "999-netbox-frr.yml",
        }

        file_suffix = file_suffixes.get(data_type, f"999-netbox-{data_type}.yml")

        if base_path:
            if base_path.is_dir():
                output_file = base_path / file_suffix
                logger.debug(f"Writing {data_type} of {device} to {output_file}")
                with open(output_file, "w+", encoding="utf-8") as fp:
                    fp.write(content)
            else:
                # For existing single file, append with separator
                logger.debug(f"Appending {data_type} of {device} to {base_path}")
                with open(base_path, "a", encoding="utf-8") as fp:
                    fp.write(f"\n# NetBox {data_type}\n")
                    fp.write(content)
        else:
            # Create new directory structure
            device_dir = self.config.inventory_path / "host_vars" / str(device)
            device_dir.mkdir(parents=True, exist_ok=True)
            output_file = device_dir / file_suffix
            logger.debug(f"Writing {data_type} of {device} to {output_file}")
            with open(output_file, "w+", encoding="utf-8") as fp:
                fp.write(content)

    def write_device_config_context(self, device: Any) -> None:
        """Legacy method for backward compatibility - writes only config context."""
        self.write_device_data(device, data_types=["config_context"])

    def write_host_groups(self, devices_to_roles: Dict[str, List[Any]]) -> None:
        """Write host groups to inventory file based on device roles.

        Args:
            devices_to_roles: Dictionary mapping role slugs to lists of devices
        """
        template = self.jinja_env.get_template("netbox.hosts.j2")
        result = template.render({"devices_to_roles": devices_to_roles})

        output_file = self.config.inventory_path / "20-netbox"
        logger.debug(f"Writing host groups from NetBox to {output_file}")
        with open(output_file, "w+", encoding="utf-8") as fp:
            # Remove empty lines
            cleaned_lines = [line for line in result.splitlines() if line]
            fp.write("\n".join(cleaned_lines))

    def write_dnsmasq_config(
        self, netbox_client: NetBoxClient, devices: List[Any]
    ) -> None:
        """Write dnsmasq DHCP configuration for devices with OOB management interfaces."""
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

                # Determine base path for device files
                host_vars_path = self.config.inventory_path / "host_vars"
                device_pattern = f"{device}*"
                result = list(host_vars_path.glob(device_pattern))

                if len(result) > 1:
                    logger.warning(
                        f"Multiple matches found for {device}, skipping dnsmasq writing"
                    )
                    continue

                base_path = result[0] if len(result) == 1 else None

                # Write to device-specific file
                if base_path:
                    if base_path.is_dir():
                        output_file = base_path / "999-netbox-dnsmasq.yml"
                        logger.debug(
                            f"Writing dnsmasq config for {device} to {output_file}"
                        )
                        with open(output_file, "w+", encoding="utf-8") as fp:
                            yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
                    else:
                        # For existing single file, append with separator
                        logger.debug(
                            f"Appending dnsmasq config for {device} to {base_path}"
                        )
                        with open(base_path, "a", encoding="utf-8") as fp:
                            fp.write("\n# NetBox dnsmasq\n")
                            yaml.dump(dnsmasq_data, fp, Dumper=yaml.Dumper)
                else:
                    # Create new directory structure
                    device_dir = self.config.inventory_path / "host_vars" / str(device)
                    device_dir.mkdir(parents=True, exist_ok=True)
                    output_file = device_dir / "999-netbox-dnsmasq.yml"
                    logger.debug(
                        f"Writing dnsmasq config for {device} to {output_file}"
                    )
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


def setup_logging() -> None:
    """Configure logging settings."""
    level = os.getenv("OSISM_LOG_LEVEL", "INFO")
    log_fmt = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
        "<level>{message}</level>"
    )
    logger.remove()
    logger.add(sys.stdout, format=log_fmt, level=level, colorize=True)


def build_device_tag_mapping(devices: List[Any]) -> Dict[str, List[Any]]:
    """Build mapping of tags to devices (legacy function)."""
    devices_to_tags = {}
    excluded_tags = {"managed-by-osism", "managed-by-ironic"}

    for device in devices:
        for tag in device.tags:
            if tag.slug not in excluded_tags:
                if tag.slug not in devices_to_tags:
                    devices_to_tags[tag.slug] = []
                devices_to_tags[tag.slug].append(device)

    return devices_to_tags


def build_device_role_mapping(
    devices: List[Any], ignored_roles: List[str] = None
) -> Dict[str, List[Any]]:
    """Build mapping of roles to devices.

    Only includes devices that have the managed-by-osism tag.
    Each device role can be mapped to multiple Ansible inventory groups.
    Default mapping includes the device role itself and 'generic' for all roles.

    Role to group mapping can be customized via environment variables:
    ROLE_MAPPING_<ROLE>="group1,group2,group3"

    Example:
    ROLE_MAPPING_COMPUTE="compute,generic,openstack"

    Args:
        devices: List of NetBox device objects
        ignored_roles: List of role slugs to skip (default: None)
    """
    devices_to_groups = {}

    # Default group mapping - can be overridden with environment variables
    default_role_mapping = {
        # Format: 'role_slug': ['group1', 'group2', ...],
        # By default, each role gets mapped to itself and to 'generic'
    }

    # Read custom role mappings from environment variables
    for key, value in os.environ.items():
        if key.startswith("ROLE_MAPPING_"):
            role_name = key[13:].lower()  # Remove 'ROLE_MAPPING_' prefix and lowercase
            groups = [group.strip() for group in value.split(",") if group.strip()]
            default_role_mapping[role_name] = groups

    if ignored_roles is None:
        ignored_roles = []

    for device in devices:
        # Skip if device has no role
        if not device.role or not device.role.slug:
            continue

        # Check if device has managed-by-osism tag
        has_managed_tag = any(tag.slug == "managed-by-osism" for tag in device.tags)
        if not has_managed_tag:
            continue

        role_slug = device.role.slug.lower()

        # Skip ignored roles
        if role_slug in ignored_roles:
            logger.debug(f"Skipping device {device} with ignored role '{role_slug}'")
            continue

        # Determine which groups this device should be assigned to
        if role_slug in default_role_mapping:
            groups = default_role_mapping[role_slug]
        else:
            # Default behavior: add to group 'generic'
            groups = ["generic"]

        # Add device to each of its groups
        for group in groups:
            if group not in devices_to_groups:
                devices_to_groups[group] = []
            if device not in devices_to_groups[group]:
                devices_to_groups[group].append(device)

    return devices_to_groups


def main() -> None:
    """Main execution function."""
    setup_logging()

    try:
        logger.info("Generate the inventory from the Netbox")

        # Load configuration
        config = Config.from_environment()

        # Initialize components
        netbox_client = NetBoxClient(config)
        inventory_manager = InventoryManager(config)

        # Fetch devices
        logger.info("Getting managed devices from NetBox. This could take some time.")
        devices_with_both_tags, devices_osism_only = netbox_client.get_managed_devices()
        all_devices = devices_with_both_tags + devices_osism_only
        logger.info(f"Found {len(all_devices)} total managed devices")

        # Process devices and build role mapping
        devices_to_roles = build_device_role_mapping(all_devices, config.ignored_roles)

        # Write device data (config context and optionally other data types)
        for device in all_devices:
            logger.info(f"Processing {device}")
            if config.data_types:
                inventory_manager.write_device_data(
                    device, data_types=config.data_types
                )
            else:
                inventory_manager.write_device_config_context(device)

        # Write host groups based on device roles
        logger.info("Generating host groups based on device roles")
        inventory_manager.write_host_groups(devices_to_roles)

        # Generate dnsmasq configuration
        logger.info("Generating dnsmasq configuration")
        inventory_manager.write_dnsmasq_config(netbox_client, all_devices)

        # Generate dnsmasq DHCP ranges
        logger.info("Generating dnsmasq DHCP ranges")
        inventory_manager.write_dnsmasq_dhcp_ranges(netbox_client)

        logger.info("NetBox inventory generation completed successfully")

    except Exception as e:
        logger.error(f"Failed to generate inventory from NetBox: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
