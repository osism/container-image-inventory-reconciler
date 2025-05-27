# SPDX-License-Identifier: Apache-2.0

"""File writing functionality for inventory management."""

from pathlib import Path
from typing import Any, Optional

from loguru import logger
import yaml

from utils import get_inventory_hostname
from .base import BaseInventoryComponent


class FileWriter(BaseInventoryComponent):
    """Handles writing inventory data to files."""

    # File suffix mapping for different data types
    FILE_SUFFIXES = {
        "config_context": "999-netbox-config-context.yml",
        "primary_ip": "999-netbox-ansible.yml",
        "netplan_parameters": "999-netbox-netplan.yml",
        "frr_parameters": "999-netbox-frr.yml",
        "dnsmasq_parameters": "999-netbox-dnsmasq.yml",
    }

    def write_device_data(self, device: Any, data_type: str, data: Any) -> None:
        """Write specific data type for a device to file.

        Args:
            device: The NetBox device object
            data_type: Type of data being written
            data: The data to write
        """
        if data is None or (isinstance(data, dict) and not data):
            logger.debug(f"No {data_type} data for device {device}, skipping")
            return

        # Find base path for device files
        base_path = self._find_device_base_path(device)

        # Prepare content
        content = self._prepare_content(data_type, data)

        # Write to file
        self._write_to_file(device, data_type, content, base_path)

    def _find_device_base_path(self, device: Any) -> Optional[Path]:
        """Find the base path for device files.

        Args:
            device: The NetBox device object

        Returns:
            Path to device directory or file, or None if not found
        """
        host_vars_path = self.config.inventory_path / "host_vars"
        device_hostname = get_inventory_hostname(device)
        device_pattern = f"{device_hostname}*"
        result = list(host_vars_path.glob(device_pattern))

        if len(result) > 1:
            logger.warning(
                f"Multiple matches found for {device_hostname}, using first match"
            )
            return result[0]

        return result[0] if len(result) == 1 else None

    def _prepare_content(self, data_type: str, data: Any) -> str:
        """Prepare content for writing based on data type.

        Args:
            data_type: Type of data being written
            data: The data to format

        Returns:
            Formatted content string
        """
        if data_type == "primary_ip":
            return f"ansible_host: {data}\n"
        elif data_type in [
            "frr_parameters",
            "netplan_parameters",
            "dnsmasq_parameters",
        ]:
            # Write these parameters directly without wrapper
            return yaml.dump(data, Dumper=yaml.Dumper)
        else:
            return yaml.dump(data, Dumper=yaml.Dumper)

    def _write_to_file(
        self, device: Any, data_type: str, content: str, base_path: Optional[Path]
    ) -> None:
        """Write content to appropriate file.

        Args:
            device: The NetBox device object
            data_type: Type of data being written
            content: Content to write
            base_path: Base path for device files
        """
        file_suffix = self.FILE_SUFFIXES.get(data_type, f"999-netbox-{data_type}.yml")

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
