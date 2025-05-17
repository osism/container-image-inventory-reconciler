# SPDX-License-Identifier: Apache-2.0

"""
Prepare Ansible variables from inventory groups.

This script generates specific Ansible variable files based on the inventory groups:
- ceph-rgw hosts configuration
- ceph-mon hosts configuration
- Ceph cluster FSID from configuration
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from loguru import logger

# Constants
GROUP_CEPH_MON = "ceph-mon"
GROUP_CEPH_RGW = "ceph-rgw"
INVENTORY_DIR = "/inventory"
INVENTORY_PRE_DIR = "/inventory.pre"
CONFIGURATION_DIR = "/opt/configuration"
RGW_DEFAULT_PORT = 8081

# File paths
INVENTORY_HOSTS_FILE = Path(INVENTORY_DIR) / "hosts.yml"
GROUP_VARS_ALL_DIR = Path(INVENTORY_PRE_DIR) / "group_vars" / "all"
CEPH_RGW_HOSTS_FILE = GROUP_VARS_ALL_DIR / "050-kolla-ceph-rgw-hosts.yml"
CEPH_MON_HOSTS_FILE = GROUP_VARS_ALL_DIR / "050-infrastructure-cephclient-mons.yml"
CEPH_FSID_FILE = GROUP_VARS_ALL_DIR / "050-ceph-cluster-fsid.yml"
CEPH_CONFIG_FILE = (
    Path(CONFIGURATION_DIR) / "environments" / "ceph" / "configuration.yml"
)

# Logger configuration
LOGGER_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)
logger.remove()
logger.add(sys.stdout, format=LOGGER_FORMAT, level="INFO", colorize=True)


def write_yaml_file(file_path: Path, data: Dict[str, Any]) -> bool:
    """
    Write data to a YAML file.

    Args:
        file_path: Path to the output file
        data: Dictionary containing the data to write

    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w") as fp:
            yaml.dump(data, fp, default_flow_style=False)
        return True
    except (OSError, IOError, yaml.YAMLError) as e:
        logger.error(f"Error writing to {file_path}: {e}")
        return False


def prepare_ceph_rgw_hosts(groups: Dict[str, List[str]]) -> int:
    """
    Prepare ceph-rgw hosts configuration.

    Args:
        groups: Dictionary of inventory groups and their hosts

    Returns:
        Number of hosts processed
    """
    if GROUP_CEPH_RGW not in groups:
        logger.debug(f"Group {GROUP_CEPH_RGW} not found in inventory")
        return 0

    hosts = []
    for host in groups[GROUP_CEPH_RGW]:
        hosts.append(
            {
                "host": str(host),
                "ip": (
                    "{{ "
                    f"hostvars['{host}']['radosgw_address'] | "
                    f"default(hostvars['{host}']['ansible_host'])"
                    " }}"
                ),
                "port": RGW_DEFAULT_PORT,
            }
        )

    if hosts:
        logger.info(f"Writing {CEPH_RGW_HOSTS_FILE.name} with ceph_rgw_hosts")
        if write_yaml_file(CEPH_RGW_HOSTS_FILE, {"ceph_rgw_hosts": hosts}):
            return len(hosts)

    return 0


def prepare_ceph_mon_hosts(groups: Dict[str, List[str]]) -> int:
    """
    Prepare ceph-mon hosts configuration.

    Args:
        groups: Dictionary of inventory groups and their hosts

    Returns:
        Number of hosts processed
    """
    if GROUP_CEPH_MON not in groups:
        logger.debug(f"Group {GROUP_CEPH_MON} not found in inventory")
        return 0

    monitors = []
    for host in groups[GROUP_CEPH_MON]:
        monitors.append(
            "{{ "
            f"hostvars['{host}']['monitor_address'] | "
            f"default(hostvars['{host}']['ansible_host'])"
            " }}"
        )

    if monitors:
        logger.info(f"Writing {CEPH_MON_HOSTS_FILE.name} with cephclient_mons")
        if write_yaml_file(CEPH_MON_HOSTS_FILE, {"cephclient_mons": monitors}):
            return len(monitors)

    return 0


def prepare_ceph_cluster_fsid() -> bool:
    """
    Extract and prepare Ceph cluster FSID from configuration.

    Returns:
        True if FSID was successfully extracted and written, False otherwise
    """
    if not CEPH_CONFIG_FILE.exists():
        logger.debug(f"Ceph configuration file not found: {CEPH_CONFIG_FILE}")
        return False

    try:
        with open(CEPH_CONFIG_FILE, "r") as fp:
            data = yaml.safe_load(fp)

        if not isinstance(data, dict) or "fsid" not in data:
            logger.debug("FSID not found in Ceph configuration")
            return False

        fsid = data["fsid"]
        logger.info(f"Writing {CEPH_FSID_FILE.name} with ceph_cluster_fsid")
        return write_yaml_file(CEPH_FSID_FILE, {"ceph_cluster_fsid": fsid})

    except (OSError, IOError) as e:
        logger.error(f"Error reading Ceph configuration: {e}")
        return False
    except yaml.YAMLError as e:
        logger.error(f"Error parsing Ceph configuration YAML: {e}")
        return False


def load_inventory() -> Optional[Dict[str, List[str]]]:
    """
    Load Ansible inventory and return groups dictionary.

    Returns:
        Dictionary of groups and their hosts, or None if loading fails
    """
    try:
        loader = DataLoader()
        inventory = InventoryManager(loader=loader, sources=[str(INVENTORY_HOSTS_FILE)])
        return inventory.get_groups_dict()
    except Exception as e:
        logger.error(f"Error loading inventory: {e}")
        return None


def main() -> None:
    """Main entry point for the prepare-vars script."""
    logger.info("Starting variable preparation from inventory")

    # Load inventory
    groups = load_inventory()
    if groups is None:
        logger.error("Failed to load inventory - aborting")
        return

    # Track statistics
    total_files_written = 0
    total_hosts_processed = 0

    # Prepare ceph-rgw hosts
    rgw_hosts = prepare_ceph_rgw_hosts(groups)
    if rgw_hosts > 0:
        total_files_written += 1
        total_hosts_processed += rgw_hosts
        logger.debug(f"Processed {rgw_hosts} ceph-rgw host(s)")

    # Prepare ceph-mon hosts
    mon_hosts = prepare_ceph_mon_hosts(groups)
    if mon_hosts > 0:
        total_files_written += 1
        total_hosts_processed += mon_hosts
        logger.debug(f"Processed {mon_hosts} ceph-mon host(s)")

    # Prepare Ceph cluster FSID
    if prepare_ceph_cluster_fsid():
        total_files_written += 1

    logger.info(
        f"{total_files_written} file(s) written, "
        f"{total_hosts_processed} host(s) processed"
    )
    logger.info("Variable preparation completed:")


if __name__ == "__main__":
    main()
