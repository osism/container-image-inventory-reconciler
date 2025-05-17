#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate ClusterShell configuration file from Ansible inventory."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from loguru import logger
import yaml


# Configure logging
LOG_LEVEL = os.getenv("OSISM_LOG_LEVEL", "INFO")
LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)

logger.remove()
logger.add(sys.stdout, format=LOG_FORMAT, level=LOG_LEVEL, colorize=True)


def run_ansible_template(
    inventory_path: Path, template_path: Path, output_path: Path
) -> None:
    """Run Ansible template module to generate ClusterShell configuration.

    Args:
        inventory_path: Path to Ansible inventory file
        template_path: Path to Jinja2 template file
        output_path: Path where the output file should be written

    Raises:
        subprocess.CalledProcessError: If Ansible command fails
    """
    ansible_cmd = [
        "ansible",
        "-i",
        str(inventory_path),
        "-m",
        "ansible.builtin.template",
        "-a",
        f"src={template_path} dest={output_path} mode=0644",
        "localhost",
    ]

    try:
        result = subprocess.run(ansible_cmd, capture_output=True, text=True, check=True)
        if result.stdout:
            logger.debug(f"Ansible output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run Ansible template command: {e}")
        if e.stderr:
            logger.error(f"Error output: {e.stderr}")
        raise


def load_clustershell_data(file_path: Path) -> Dict[str, Any]:
    """Load ClusterShell data from YAML file.

    Args:
        file_path: Path to the YAML file

    Returns:
        Dictionary containing ClusterShell configuration

    Raises:
        FileNotFoundError: If file doesn't exist
        yaml.YAMLError: If YAML parsing fails
    """
    try:
        with open(file_path, "r") as fp:
            return yaml.safe_load(fp)
    except FileNotFoundError:
        logger.error(f"ClusterShell file not found: {file_path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML file: {e}")
        raise


def sort_ansible_groups(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sort hosts within each Ansible group alphabetically.

    Args:
        data: Dictionary containing ClusterShell configuration

    Returns:
        Dictionary with sorted host lists
    """
    if "ansible" not in data:
        logger.warning("No 'ansible' section found in data")
        return data

    for group_name, hosts in data["ansible"].items():
        if isinstance(hosts, list):
            data["ansible"][group_name] = sorted(hosts)
            logger.debug(f"Sorted {len(hosts)} hosts in group '{group_name}'")

    return data


def save_clustershell_data(data: Dict[str, Any], file_path: Path) -> None:
    """Save ClusterShell data to YAML file.

    Args:
        data: Dictionary containing ClusterShell configuration
        file_path: Path where the file should be written
    """
    try:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w") as fp:
            yaml.dump(
                data, fp, default_flow_style=False, sort_keys=False, allow_unicode=True
            )
        logger.info("Successfully wrote ClusterShell configuration")
    except OSError as e:
        logger.error(f"Failed to write file: {e}")
        raise


def main():
    """Main function to generate ClusterShell configuration file."""
    # Define paths
    inventory_path = Path("/inventory/hosts.yml")
    template_path = Path("/templates/clustershell.yml.j2")
    output_path = Path("/inventory/clustershell/ansible.yaml")

    try:
        # Generate initial ClusterShell file using Ansible template
        logger.info("Generating ClusterShell configuration from Ansible inventory")
        run_ansible_template(inventory_path, template_path, output_path)

        # Load and sort the generated data
        logger.debug("Loading generated ClusterShell data")
        data = load_clustershell_data(output_path)

        # Sort hosts within each group
        logger.debug("Sorting hosts within groups")
        sorted_data = sort_ansible_groups(data)

        # Save the sorted data
        save_clustershell_data(sorted_data, output_path)

    except Exception as e:
        logger.error(f"Failed to generate ClusterShell configuration: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
