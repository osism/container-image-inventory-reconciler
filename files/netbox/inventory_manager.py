# SPDX-License-Identifier: Apache-2.0

"""Inventory file management functionality."""

from pathlib import Path
from typing import Any, Dict, List, Optional

import jinja2
from loguru import logger
import yaml

from config import Config
from data_extractor import DeviceDataExtractor
from utils import get_inventory_hostname


class InventoryManager:
    """Manages inventory file operations."""

    def __init__(self, config: Config, api=None, netbox_client=None):
        self.config = config
        self.data_extractor = DeviceDataExtractor(api=api, netbox_client=netbox_client)
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath=str(config.template_path))
        )
        # Cache for extracted device data
        self._extracted_data_cache = {}

    def extract_device_data(self, device: Any, data_types: List[str] = None) -> None:
        """Extract various device data types and cache them.

        Args:
            device: The NetBox device object
            data_types: List of data types to extract.
                       If None, only config_context will be used.
        """
        if data_types is None:
            data_types = ["config_context", "primary_ip"]

        # Extract all requested data and cache it
        all_data = self.data_extractor.extract_all_data(
            device,
            self.config.default_mtu,
            self.config.default_local_as_prefix,
            self.config.frr_switch_roles,
            self.config.flush_cache,
        )

        # Store in cache for later use
        device_name = get_inventory_hostname(device)
        self._extracted_data_cache[device_name] = all_data
        logger.debug(f"Extracted and cached data for device {device_name}")

    def extract_device_config_context(self, device: Any) -> None:
        """Extract only config context and cache it."""
        self.extract_device_data(device, data_types=["config_context"])

    def write_device_data(self, device: Any, data_types: List[str] = None) -> None:
        """Write various device data types to appropriate files.

        Args:
            device: The NetBox device object
            data_types: List of data types to extract and write.
                       If None, only config_context will be used.
        """
        if data_types is None:
            data_types = ["config_context", "primary_ip"]

        # Get cached data if available, otherwise extract it
        device_name = get_inventory_hostname(device)
        if device_name in self._extracted_data_cache:
            all_data = self._extracted_data_cache[device_name]
            logger.debug(f"Using cached data for device {device_name}")
        else:
            # Extract all requested data if not cached
            all_data = self.data_extractor.extract_all_data(
                device,
                self.config.default_mtu,
                self.config.default_local_as_prefix,
                self.config.frr_switch_roles,
            )

        # Determine base path for device files
        host_vars_path = self.config.inventory_path / "host_vars"
        device_hostname = get_inventory_hostname(device)
        device_pattern = f"{device_hostname}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {device_hostname}, skipping data writing"
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
        elif data_type == "frr_parameters":
            # For frr_parameters, write the content directly without wrapper
            content = yaml.dump(data, Dumper=yaml.Dumper)
        elif data_type == "netplan_parameters":
            # For netplan_parameters, write the content directly without wrapper
            content = yaml.dump(data, Dumper=yaml.Dumper)
        elif data_type == "dnsmasq_parameters":
            # For dnsmasq_parameters, write the content directly without wrapper
            content = yaml.dump(data, Dumper=yaml.Dumper)
        else:
            content = yaml.dump(data, Dumper=yaml.Dumper)

        # Determine file naming convention based on data type
        file_suffixes = {
            "config_context": "999-netbox-config-context.yml",
            "primary_ip": "999-netbox-ansible.yml",
            "netplan_parameters": "999-netbox-netplan.yml",
            "frr_parameters": "999-netbox-frr.yml",
            "dnsmasq_parameters": "999-netbox-dnsmasq.yml",
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
            device_hostname = get_inventory_hostname(device)
            device_dir = self.config.inventory_path / "host_vars" / device_hostname
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
