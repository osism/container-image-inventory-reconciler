#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Generate a minified hosts.yml containing only hosts and their group memberships.

Also generates a fast inventory directory with a JSON-based inventory file
and separate host_vars/group_vars directories for lazy loading by Ansible.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from loguru import logger
import yaml


# Allow safe_load to handle Ansible Vault !vault tags
yaml.SafeLoader.add_constructor(
    "!vault", lambda loader, node: loader.construct_scalar(node)
)


# Configure logging
LOG_LEVEL = os.getenv("OSISM_LOG_LEVEL", "INFO")
LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)

logger.remove()
logger.add(sys.stdout, format=LOG_FORMAT, level=LOG_LEVEL, colorize=True)


def strip_hostvars(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively strip host variables from inventory structure.

    Walks the inventory tree and replaces all host variable dictionaries
    with empty dicts, preserving only the group hierarchy and host memberships.

    Args:
        data: Ansible inventory data structure

    Returns:
        Inventory structure with all host variables removed
    """
    if not isinstance(data, dict):
        return data

    result = {}
    for key, value in data.items():
        if key == "hosts" and isinstance(value, dict):
            result["hosts"] = {hostname: {} for hostname in value}
        elif key == "children" and isinstance(value, dict):
            result["children"] = {
                group: strip_hostvars(group_data) for group, group_data in value.items()
            }
        elif key == "vars":
            continue
        else:
            if isinstance(value, dict):
                result[key] = strip_hostvars(value)
            else:
                result[key] = value
    return result


def generate_fast_inventory(minified: Dict[str, Any]) -> None:
    """Generate JSON-based fast inventory file.

    Writes the minified inventory structure as JSON to the fast inventory
    directory. This file is used together with host_vars/ and group_vars/
    directories (copied by run.sh) to provide a fast inventory that Ansible
    can parse significantly faster than the monolithic YAML hosts.yml.

    JSON parsing is 26-200x faster than YAML parsing in Python.
    Combined with Ansible's lazy loading of host_vars/ files, this
    dramatically reduces inventory ramp-up time for large environments.

    Args:
        minified: Inventory structure with hostvars/groupvars stripped
    """
    fast_dir = Path("/inventory.merge/fast")
    fast_dir.mkdir(parents=True, exist_ok=True)

    output_path = fast_dir / "hosts.json"

    with open(output_path, "w") as fp:
        json.dump(minified, fp, ensure_ascii=False, separators=(",", ":"))

    logger.info(f"Successfully wrote fast inventory to {output_path}")


def main():
    """Main function to generate minified hosts file and fast inventory."""
    input_path = Path("/inventory.merge/hosts.yml")
    output_path = Path("/inventory.merge/hosts-minified.yml")

    try:
        logger.info("Generating minified hosts file")

        with open(input_path, "r") as fp:
            inventory = yaml.safe_load(fp)

        minified = strip_hostvars(inventory)

        with open(output_path, "w") as fp:
            yaml.dump(
                minified,
                fp,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

        logger.info(f"Successfully wrote minified hosts file to {output_path}")

        generate_fast_inventory(minified)

    except FileNotFoundError:
        logger.error(f"Inventory file not found: {input_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML: {e}")
        sys.exit(1)
    except OSError as e:
        logger.error(f"File operation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
