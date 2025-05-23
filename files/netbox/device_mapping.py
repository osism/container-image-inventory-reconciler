# SPDX-License-Identifier: Apache-2.0

"""Device mapping and grouping functionality."""

from typing import Any, Dict, List

from loguru import logger

from config import SETTINGS


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

    Role to group mapping can be customized via NETBOX_ROLE_MAPPING environment variable
    which should contain a JSON dictionary:
    NETBOX_ROLE_MAPPING='{"compute": ["generic", "compute"], "manager": ["generic", "manager"]}'

    Args:
        devices: List of NetBox device objects
        ignored_roles: List of role slugs to skip (default: None)
    """
    devices_to_groups = {}

    # Read role mappings from NETBOX_ROLE_MAPPING environment variable
    role_mapping = SETTINGS.get("NETBOX_ROLE_MAPPING", {})

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
        if role_slug in role_mapping:
            groups = role_mapping[role_slug]
            if not isinstance(groups, list):
                logger.warning(
                    f"Role mapping for '{role_slug}' is not a list, using default"
                )
                groups = ["generic"]
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
