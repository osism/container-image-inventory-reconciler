# SPDX-License-Identifier: Apache-2.0

"""File writing functionality for inventory management."""

import re
from pathlib import Path
from typing import Any, Optional

from loguru import logger
import yaml

from utils import get_inventory_hostname
from .base import BaseInventoryComponent


def _vault_string_representer(dumper, data):
    """YAML representer that emits Ansible Vault strings with !vault tag."""
    return dumper.represent_scalar("!vault", data, style="|")


class _VaultString(str):
    """Marker type for Ansible Vault encrypted strings."""


# Build a Dumper that automatically handles vault strings
VaultAwareDumper = type("VaultAwareDumper", (yaml.Dumper,), {})
VaultAwareDumper.add_representer(_VaultString, _vault_string_representer)


def _tag_vault_strings(obj):
    """Recursively wrap vault-encrypted strings so the custom Dumper picks them up."""
    if isinstance(obj, dict):
        return {k: _tag_vault_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_tag_vault_strings(v) for v in obj]
    if isinstance(obj, str) and obj.strip().startswith("$ANSIBLE_VAULT;"):
        return _VaultString(obj)
    return obj


class FileWriter(BaseInventoryComponent):
    """Handles writing inventory data to files."""

    # File suffix mapping for different data types
    FILE_SUFFIXES = {
        "config_context": "999-netbox-config-context.yml",
        "primary_ip": "999-netbox-ansible.yml",
        "netplan_parameters": "999-netbox-netplan.yml",
        "frr_parameters": "999-netbox-frr.yml",
        "dnsmasq_parameters": "999-netbox-dnsmasq.yml",
        "gnmic_parameters": "999-netbox-gnmic.yml",
        "secrets": "999-netbox-secrets.yml",
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

        # For single-file host_vars, filter out keys that are already defined
        # manually (outside of NetBox sections) - manual definitions take priority
        if base_path and not base_path.is_dir() and isinstance(data, dict):
            data = self._filter_existing_manual_keys(base_path, data_type, data, device)
            if not data:
                logger.debug(
                    f"All {data_type} keys for device {device} already defined "
                    f"manually in {base_path}, skipping"
                )
                return

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

        Any string value starting with ``$ANSIBLE_VAULT;`` is automatically
        serialized with the ``!vault`` YAML tag regardless of data type.

        Args:
            data_type: Type of data being written
            data: The data to format

        Returns:
            Formatted content string
        """
        if data_type == "primary_ip":
            return f"ansible_host: {data}\n"
        else:
            # All other data types (config_context, frr_parameters,
            # netplan_parameters, dnsmasq_parameters, gnmic_parameters,
            # secrets, ...) are written as YAML with vault-aware serialization.
            return yaml.dump(_tag_vault_strings(data), Dumper=VaultAwareDumper)

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
                # For existing single file, remove existing NetBox section first,
                # then append with separator to avoid duplicate keys
                logger.debug(f"Updating {data_type} of {device} in {base_path}")
                existing_content = self._remove_existing_netbox_section(
                    base_path, data_type
                )
                with open(base_path, "w", encoding="utf-8") as fp:
                    fp.write(existing_content)
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

    def _remove_existing_netbox_section(self, file_path: Path, data_type: str) -> str:
        """Remove existing NetBox section from a file.

        This method reads a file and removes any existing section that starts
        with "# NetBox {data_type}" to prevent duplicate keys when the file
        is updated on subsequent runs.

        Args:
            file_path: Path to the file to process
            data_type: Type of data section to remove

        Returns:
            File content with the specified NetBox section removed
        """
        try:
            with open(file_path, "r", encoding="utf-8") as fp:
                content = fp.read()
        except FileNotFoundError:
            return ""

        section_marker = f"# NetBox {data_type}"
        if section_marker not in content:
            return content

        # Find the start of the section to remove
        lines = content.split("\n")
        result_lines = []
        skip_section = False

        for line in lines:
            # Check if this line starts a NetBox section
            if line.startswith("# NetBox "):
                if line == section_marker:
                    # Start skipping this section
                    skip_section = True
                    continue
                else:
                    # Different NetBox section, stop skipping
                    skip_section = False

            if not skip_section:
                result_lines.append(line)

        # Remove trailing empty lines that might have been left
        while result_lines and result_lines[-1] == "":
            result_lines.pop()

        return "\n".join(result_lines)

    def _filter_existing_manual_keys(
        self, file_path: Path, data_type: str, data: dict, device: Any
    ) -> dict:
        """Filter out keys that are already defined manually in the file.

        Manual definitions (outside of NetBox sections) take priority over
        NetBox-generated values. This prevents duplicate key warnings when
        a key is defined both manually and generated by NetBox.

        Args:
            file_path: Path to the host_vars file
            data_type: Type of data being written
            data: Dictionary of data to filter
            device: The NetBox device object (for logging)

        Returns:
            Filtered dictionary with manually-defined keys removed
        """
        manual_keys = self._get_manual_yaml_keys(file_path, data_type)
        if not manual_keys:
            return data

        # Filter out keys that are already defined manually
        filtered_data = {}
        for key, value in data.items():
            if key in manual_keys:
                logger.info(
                    f"Skipping NetBox-generated '{key}' for device {device} - "
                    f"already defined manually in {file_path}"
                )
            else:
                filtered_data[key] = value

        return filtered_data

    def _get_manual_yaml_keys(self, file_path: Path, data_type: str) -> set:
        """Extract top-level YAML keys that are defined outside NetBox sections.

        Args:
            file_path: Path to the YAML file
            data_type: Type of data section to exclude from manual keys

        Returns:
            Set of top-level keys defined manually (outside NetBox sections)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as fp:
                content = fp.read()
        except FileNotFoundError:
            return set()

        if not content.strip():
            return set()

        # Split content into manual part and NetBox sections
        lines = content.split("\n")
        manual_lines = []
        in_netbox_section = False

        for line in lines:
            # Check if this line starts a NetBox section
            if line.startswith("# NetBox "):
                in_netbox_section = True
                continue

            # A non-indented, non-empty, non-comment line outside NetBox section
            # might be a top-level key
            if not in_netbox_section:
                manual_lines.append(line)

        # Parse the manual part as YAML to extract top-level keys
        manual_content = "\n".join(manual_lines)
        if not manual_content.strip():
            return set()

        try:
            manual_data = yaml.safe_load(manual_content)
            if isinstance(manual_data, dict):
                return set(manual_data.keys())
        except yaml.YAMLError:
            # If parsing fails, try to extract keys by simple pattern matching
            # Look for lines that start with a word followed by colon (top-level keys)
            keys = set()
            for line in manual_lines:
                match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):", line)
                if match:
                    keys.add(match.group(1))
            return keys

        return set()
