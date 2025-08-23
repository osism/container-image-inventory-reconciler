# SPDX-License-Identifier: Apache-2.0

"""Cluster and cluster group mapping functionality."""

from typing import Any, Dict, List

from loguru import logger

from utils import get_inventory_hostname


def normalize_name(name: str) -> str:
    """Normalize cluster/cluster group names for Ansible inventory.

    Convert to lowercase and replace spaces and dashes with underscores.

    Args:
        name: Original name from NetBox

    Returns:
        Normalized name suitable for Ansible group names
    """
    return name.lower().replace(" ", "_").replace("-", "_")


def build_cluster_mapping(
    devices: List[Any], clusters: List[Any], cluster_groups: List[Any]
) -> Dict[str, Any]:
    """Build mapping of clusters and cluster groups to devices.

    Args:
        devices: List of NetBox device objects (filtered by netbox_filter_inventory)
        clusters: List of NetBox cluster objects
        cluster_groups: List of NetBox cluster group objects

    Returns:
        Dictionary with cluster and cluster group mappings:
        {
            'cluster_groups': {
                'normalized_cluster_group_name': {
                    'original_name': 'Original Name',
                    'clusters': ['normalized_cluster1', 'normalized_cluster2'],
                    'devices': [],  # direct assignments if any
                    'config_context': {}  # cluster group config context
                }
            },
            'clusters': {
                'normalized_cluster_name': {
                    'original_name': 'Original Name',
                    'cluster_group': 'normalized_parent_group_name',  # nullable
                    'devices': ['device_hostname1', 'device_hostname2'],
                    'config_context': {}  # cluster config context
                }
            }
        }
    """
    cluster_mapping = {"cluster_groups": {}, "clusters": {}}

    # Build cluster group mapping
    cluster_group_id_to_name = {}
    for cluster_group in cluster_groups:
        normalized_name = normalize_name(cluster_group.name)
        cluster_mapping["cluster_groups"][normalized_name] = {
            "original_name": cluster_group.name,
            "clusters": [],
            "devices": [],
            "config_context": getattr(cluster_group, "config_context", {}) or {},
        }
        cluster_group_id_to_name[cluster_group.id] = normalized_name
        logger.debug(f"Added cluster group: {cluster_group.name} -> {normalized_name}")

    # Build cluster mapping and link to cluster groups
    cluster_id_to_name = {}
    for cluster in clusters:
        normalized_name = normalize_name(cluster.name)
        cluster_group_name = None

        # Check if cluster belongs to a cluster group
        if (
            hasattr(cluster, "group")
            and cluster.group
            and cluster.group.id in cluster_group_id_to_name
        ):
            cluster_group_name = cluster_group_id_to_name[cluster.group.id]
            # Add this cluster to its parent cluster group
            cluster_mapping["cluster_groups"][cluster_group_name]["clusters"].append(
                normalized_name
            )

        cluster_mapping["clusters"][normalized_name] = {
            "original_name": cluster.name,
            "cluster_group": cluster_group_name,
            "devices": [],
            "config_context": getattr(cluster, "config_context", {}) or {},
        }
        cluster_id_to_name[cluster.id] = normalized_name
        logger.debug(
            f"Added cluster: {cluster.name} -> {normalized_name}, group: {cluster_group_name}"
        )

    # Map devices to clusters
    devices_in_clusters = set()
    for device in devices:
        # Skip if device has no cluster assignment
        if not hasattr(device, "cluster") or not device.cluster:
            continue

        # Skip if device doesn't have managed-by-osism tag
        has_managed_tag = any(tag.slug == "managed-by-osism" for tag in device.tags)
        if not has_managed_tag:
            continue

        cluster_id = device.cluster.id
        if cluster_id in cluster_id_to_name:
            cluster_name = cluster_id_to_name[cluster_id]
            device_hostname = get_inventory_hostname(device)
            cluster_mapping["clusters"][cluster_name]["devices"].append(device_hostname)
            devices_in_clusters.add(device.name)
            logger.debug(f"Added device {device_hostname} to cluster {cluster_name}")

    # Log summary
    total_cluster_groups = len(cluster_mapping["cluster_groups"])
    total_clusters = len(cluster_mapping["clusters"])
    total_devices_in_clusters = len(devices_in_clusters)

    logger.info(
        f"Cluster mapping: {total_cluster_groups} cluster groups, "
        f"{total_clusters} clusters, {total_devices_in_clusters} devices in clusters"
    )

    return cluster_mapping


def build_cluster_inventory_groups(
    cluster_mapping: Dict[str, Any]
) -> Dict[str, List[str]]:
    """Convert cluster mapping to Ansible inventory group format.

    Args:
        cluster_mapping: Result from build_cluster_mapping()

    Returns:
        Dictionary mapping Ansible group names to lists of hosts/children
        {
            'cluster_group_name': [],  # Empty list for cluster groups
            'cluster_name:children': ['cluster_group_name'],  # Children relationships
            'cluster_name': ['device1', 'device2']  # Device assignments
        }
    """
    inventory_groups = {}

    # Add cluster groups (empty groups that serve as parents)
    for group_name, group_data in cluster_mapping["cluster_groups"].items():
        inventory_groups[group_name] = []
        logger.debug(f"Added cluster group: {group_name}")

    # Add clusters and their relationships
    for cluster_name, cluster_data in cluster_mapping["clusters"].items():
        # Add devices to cluster group
        inventory_groups[cluster_name] = cluster_data["devices"]

        # If cluster belongs to a cluster group, establish parent-child relationship
        if cluster_data["cluster_group"]:
            children_key = f"{cluster_name}:children"
            inventory_groups[children_key] = [cluster_data["cluster_group"]]
            logger.debug(
                f"Added cluster {cluster_name} as child of {cluster_data['cluster_group']}"
            )

        logger.debug(
            f"Added cluster {cluster_name} with {len(cluster_data['devices'])} devices"
        )

    return inventory_groups


def extract_cluster_config_contexts(
    cluster_mapping: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """Extract config contexts from clusters and cluster groups that have them.

    Args:
        cluster_mapping: Result from build_cluster_mapping()

    Returns:
        Dictionary mapping normalized group names to their config contexts
        {
            'normalized_group_name': {'config_context_key': 'value', ...}
        }
    """
    config_contexts = {}

    # Extract cluster group config contexts
    for group_name, group_data in cluster_mapping["cluster_groups"].items():
        config_context = group_data.get("config_context", {})
        if config_context:
            config_contexts[group_name] = config_context
            logger.debug(f"Found config context for cluster group {group_name}")

    # Extract cluster config contexts
    for cluster_name, cluster_data in cluster_mapping["clusters"].items():
        config_context = cluster_data.get("config_context", {})
        if config_context:
            config_contexts[cluster_name] = config_context
            logger.debug(f"Found config context for cluster {cluster_name}")

    logger.info(
        f"Extracted config contexts for {len(config_contexts)} cluster groups/clusters"
    )
    return config_contexts
