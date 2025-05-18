# SPDX-License-Identifier: Apache-2.0

"""NetBox inventory generator for OSISM.

This script reads all required systems from the NetBox and writes them
into a form that can be evaluated by the Ansible Inventory Plugin INI.

This is a workaround to use the groups defined in cfg-generics without
having to import them into NetBox.
"""

import glob
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Any, Tuple, Optional

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
    inventory_path: str = "/inventory.pre"
    template_path: str = "/templates/"
    data_types: List[str] = None  # Configurable data types to extract

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

        return cls(
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            ignore_ssl_errors=os.getenv("IGNORE_SSL_ERRORS", "True") == "True",
            data_types=data_types,
        )

    @staticmethod
    def _read_secret(secret_name: str) -> str:
        """Read secret from file."""
        try:
            with open(f"/run/secrets/{secret_name}", "r", encoding="utf-8") as f:
                return f.readline().strip()
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
            return device.primary_ip.address
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
            loader=jinja2.FileSystemLoader(searchpath=config.template_path)
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
        host_vars_pattern = f"{self.config.inventory_path}/host_vars/{device}*"
        result = glob.glob(host_vars_pattern)

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
        self, device: Any, data_type: str, data: Any, base_path: Optional[str]
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

        file_suffix = file_suffixes.get(data_type, f"990-netbox-{data_type}.yml")

        if base_path:
            if os.path.isdir(base_path):
                output_file = f"{base_path}/{file_suffix}"
                logger.debug(f"Writing NetBox {data_type} of {device} to {output_file}")
                with open(output_file, "w+") as fp:
                    fp.write(content)
            else:
                # For existing single file, append with separator
                logger.debug(f"Appending NetBox {data_type} of {device} to {base_path}")
                with open(base_path, "a") as fp:
                    fp.write(f"\n# NetBox {data_type}\n")
                    fp.write(content)
        else:
            # Create new directory structure
            device_dir = f"{self.config.inventory_path}/host_vars/{device}"
            os.makedirs(device_dir, exist_ok=True)
            output_file = f"{device_dir}/{file_suffix}"
            logger.debug(f"Writing NetBox {data_type} of {device} to {output_file}")
            with open(output_file, "w+") as fp:
                fp.write(content)

    def write_device_config_context(self, device: Any) -> None:
        """Legacy method for backward compatibility - writes only config context."""
        self.write_device_data(device, data_types=["config_context"])

    def write_host_groups(self, devices_to_tags: Dict[str, List[Any]]) -> None:
        """Write host groups to inventory file."""
        template = self.jinja_env.get_template("netbox.hosts.j2")
        result = template.render({"devices_to_tags": devices_to_tags})

        output_file = f"{self.config.inventory_path}/20-netbox"
        logger.debug(f"Writing host groups from NetBox to {output_file}")
        with open(output_file, "w+") as fp:
            # Remove empty lines
            fp.write(os.linesep.join([s for s in result.splitlines() if s]))


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
    """Build mapping of tags to devices."""
    devices_to_tags = {}
    excluded_tags = {"managed-by-osism", "managed-by-ironic"}

    for device in devices:
        for tag in device.tags:
            if tag.slug not in excluded_tags:
                if tag.slug not in devices_to_tags:
                    devices_to_tags[tag.slug] = []
                devices_to_tags[tag.slug].append(device)

    return devices_to_tags


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

        # Process devices and build tag mapping
        devices_to_tags = build_device_tag_mapping(all_devices)

        # Write device data (config context and optionally other data types)
        for device in all_devices:
            logger.info(f"Processing {device}")
            if config.data_types:
                inventory_manager.write_device_data(
                    device, data_types=config.data_types
                )
            else:
                inventory_manager.write_device_config_context(device)

        # Write host groups
        logger.info("Generating host groups")
        inventory_manager.write_host_groups(devices_to_tags)

        logger.info("NetBox inventory generation completed successfully")

    except Exception as e:
        logger.error(f"Failed to generate inventory from NetBox: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
