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
from typing import Dict, List, Any, Tuple

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

    @classmethod
    def from_environment(cls) -> "Config":
        """Create configuration from environment variables."""
        netbox_url = os.getenv("NETBOX_API")
        if not netbox_url:
            raise ValueError("NETBOX_API environment variable is required")

        netbox_token = os.getenv("NETBOX_TOKEN", cls._read_secret("NETBOX_TOKEN"))
        if not netbox_token:
            raise ValueError("NETBOX_TOKEN not found in environment or secrets")

        return cls(
            netbox_url=netbox_url,
            netbox_token=netbox_token,
            ignore_ssl_errors=os.getenv("IGNORE_SSL_ERRORS", "True") == "True",
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
            cf_maintenance=[False],
            cf_provision_state=["active"],
        )

        # Second set: Nodes with managed-by-osism but NOT managed-by-ironic
        # For these, cf_provision_state is not evaluated
        devices_osism_only = self.api.dcim.devices.filter(
            tag=["managed-by-osism"],
            status="active",
            cf_maintenance=[False],
        )
        # Filter out devices that also have managed-by-ironic tag
        devices_osism_only_filtered = [
            device
            for device in devices_osism_only
            if "managed-by-ironic" not in [tag.slug for tag in device.tags]
        ]

        return list(devices_with_both_tags), devices_osism_only_filtered


class InventoryManager:
    """Manages inventory file operations."""

    def __init__(self, config: Config):
        self.config = config
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath=config.template_path)
        )

    def write_device_config_context(self, device: Any) -> None:
        """Write device config context to appropriate location."""
        config_context = yaml.dump(device.config_context, Dumper=yaml.Dumper)
        host_vars_pattern = f"{self.config.inventory_path}/host_vars/{device}*"
        result = glob.glob(host_vars_pattern)

        if len(result) == 1:
            self._write_to_existing_location(device, result[0], config_context)
        elif len(result) == 0:
            self._write_to_new_location(device, config_context)
        else:
            logger.warning(
                f"Multiple matches found for {device}, skipping config context"
            )

    def _write_to_existing_location(self, device: Any, path: str, content: str) -> None:
        """Write config context to existing location."""
        if os.path.isdir(path):
            output_file = f"{path}/999-netbox.yml"
            logger.info(f"Writing NetBox config context of {device} to {output_file}")
            with open(output_file, "w+") as fp:
                fp.write(content)
        else:
            logger.info(f"Appending NetBox config context of {device} to {path}")
            with open(path, "a") as fp:
                fp.write(content)

    def _write_to_new_location(self, device: Any, content: str) -> None:
        """Write config context to new location."""
        output_file = f"{self.config.inventory_path}/host_vars/{device}.yml"
        logger.info(f"Writing NetBox config context of {device} to {output_file}")
        with open(output_file, "w+") as fp:
            fp.write(content)

    def write_host_groups(self, devices_to_tags: Dict[str, List[Any]]) -> None:
        """Write host groups to inventory file."""
        template = self.jinja_env.get_template("netbox.hosts.j2")
        result = template.render({"devices_to_tags": devices_to_tags})

        output_file = f"{self.config.inventory_path}/20-netbox"
        logger.info(f"Writing host groups from NetBox to {output_file}")
        with open(output_file, "w+") as fp:
            # Remove empty lines
            fp.write(os.linesep.join([s for s in result.splitlines() if s]))


def setup_logging() -> None:
    """Configure logging settings."""
    level = "INFO"
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
        devices_with_both_tags, devices_osism_only = netbox_client.get_managed_devices()
        all_devices = devices_with_both_tags + devices_osism_only
        logger.debug(f"Found {len(all_devices)} total managed devices")

        # Process devices and build tag mapping
        devices_to_tags = build_device_tag_mapping(all_devices)

        # Write device config contexts
        for device in all_devices:
            inventory_manager.write_device_config_context(device)

        # Write host groups
        inventory_manager.write_host_groups(devices_to_tags)

        logger.info("NetBox inventory generation completed successfully")

    except Exception as e:
        logger.error(f"Failed to generate inventory from NetBox: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
