# SPDX-License-Identifier: Apache-2.0

"""Utility functions for NetBox integration."""

import sys

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
