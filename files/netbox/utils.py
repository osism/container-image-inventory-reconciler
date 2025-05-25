# SPDX-License-Identifier: Apache-2.0

"""Utility functions for NetBox integration."""

import sys
from typing import Any

from loguru import logger

from config import SETTINGS


def setup_logging() -> None:
    """Configure logging settings."""
    level = SETTINGS.get("OSISM_LOG_LEVEL", "INFO")
    log_fmt = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
        "<level>{message}</level>"
    )
    logger.remove()
    logger.add(sys.stdout, format=log_fmt, level=level, colorize=True)


def get_inventory_hostname(device: Any) -> str:
    """Get the inventory hostname for a device.

    If the device has an 'inventory_hostname' custom field set, use that.
    Otherwise, fall back to the device name.

    Args:
        device: NetBox device object

    Returns:
        The hostname to use in the inventory
    """
    custom_fields = device.custom_fields or {}
    inventory_hostname = custom_fields.get("inventory_hostname")

    if inventory_hostname:
        return str(inventory_hostname)

    return str(device.name)
