# SPDX-License-Identifier: Apache-2.0

"""
Merge inventory files in the /inventory.pre directory.

This script reads two files in the /inventory.pre directory (if it exists)
and merges them into a new file in the same directory. The merge operation
combines sections and key-value pairs from both files, with the second file's
content taking precedence.
"""

import configparser
from io import StringIO
import os
import re
import sys
from pathlib import Path
from typing import Optional

from loguru import logger

# Constants
DEFAULT_INVENTORY_DIR = "/inventory.pre/"

# Logger configuration
LOGGER_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)
logger.remove()
logger.add(
    sys.stdout,
    format=LOGGER_FORMAT,
    level=os.getenv("OSISM_LOG_LEVEL", "INFO"),
    colorize=True,
)


def read_config_file(filepath: Path) -> Optional[configparser.ConfigParser]:
    """
    Read a configuration file with proper error handling.

    Args:
        filepath: Path to the configuration file

    Returns:
        Configured ConfigParser object or None if error occurs
    """
    try:
        config = configparser.ConfigParser(
            allow_no_value=True
        )
        config.read(filepath)
        return config
    except (UnicodeDecodeError, configparser.Error) as e:
        logger.error(f"Error reading file {filepath}: {e}")
        return None


def write_config_file(config: configparser.ConfigParser, filepath: Path) -> bool:
    """
    Write configuration to a file.

    Args:
        config: ConfigParser object to write
        filepath: Path to write the configuration to

    Returns:
        True if successful, False otherwise
    """

    output = StringIO()
    config.write(output)
    content = output.getvalue()
    content = re.sub(r'^(\w+)\s*=\s*$', r'\1', content, flags=re.MULTILINE)

    try:
        with open(filepath, "w") as fp:
            fp.write(content)
        return True
    except (IOError, OSError) as e:
        logger.error(f"Error writing file {filepath}: {e}")
        return False


def merge_configs(
    config1: configparser.ConfigParser, config2: configparser.ConfigParser
) -> None:
    """
    Merge config2 into config1, with config2 taking precedence.

    Args:
        config1: Target configuration (will be modified)
        config2: Source configuration to merge from
    """
    for section in config2.sections():
        if not config1.has_section(section):
            config1.add_section(section)
        for key, value in config2.items(section):
            config1.set(section, key, value)


def merge_inventory_files(
    source1: str, source2: str, target: str, dirname: str = DEFAULT_INVENTORY_DIR
) -> bool:
    """
    Merge two inventory files into a target file.

    This function reads two source files, merges their content (with source2
    taking precedence), and writes the result to a target file. The original
    source files are removed after successful merge.

    Args:
        source1: First source file name
        source2: Second source file name (takes precedence)
        target: Target file name for the merged content
        dirname: Directory containing the files

    Returns:
        True if merge was successful, False otherwise
    """
    # Convert to Path objects for better path handling
    dir_path = Path(dirname)
    source1_path = dir_path / source1
    source2_path = dir_path / source2
    target_path = dir_path / target

    # Check if both source files exist
    if not source1_path.is_file():
        logger.debug(f"File {source1} not found in {dirname}")
        return False

    if not source2_path.is_file():
        logger.debug(f"File {source2} not found in {dirname}")
        return False

    logger.info(f"Merging {source1} and {source2} into {target}")

    # Read both configuration files
    config1 = read_config_file(source1_path)
    if config1 is None:
        return False

    config2 = read_config_file(source2_path)
    if config2 is None:
        return False

    # Merge configurations
    merge_configs(config1, config2)

    # Remove original files only after successful write
    try:
        source1_path.unlink()
        source2_path.unlink()
        logger.debug("Successfully removed source files")
    except (IOError, OSError) as e:
        logger.error(f"Error removing source files: {e}")

    # Write the merged configuration
    if not write_config_file(config1, target_path):
        return False

    return True


def main() -> None:
    """Main entry point for the script."""
    logger.info("Starting merge of inventory files")
    merge_inventory_files("20-roles", "20-netbox", "20-roles")
    logger.info("Inventory files merged successfully")


if __name__ == "__main__":
    main()
