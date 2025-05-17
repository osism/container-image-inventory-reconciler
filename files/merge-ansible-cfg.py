# SPDX-License-Identifier: Apache-2.0

"""
Merge multiple Ansible configuration files into a single output file.

This script reads Ansible configuration files from defaults and user configuration
directories, merges them using ConfigParser, and writes the merged configuration
to the inventory directory. The user configuration takes precedence over defaults.
"""

import configparser
import sys
from pathlib import Path
from typing import List, Optional

from loguru import logger

# Constants
DEFAULT_CONFIG_PATH = "/defaults/ansible.cfg"
USER_CONFIG_PATH = "/opt/configuration/environments/ansible.cfg"
OUTPUT_CONFIG_PATH = "/inventory/ansible/ansible.cfg"

# Logger configuration
LOGGER_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)
logger.remove()
logger.add(sys.stdout, format=LOGGER_FORMAT, level="INFO", colorize=True)


def validate_config_files(config_paths: List[str]) -> List[str]:
    """
    Validate that configuration files exist and are readable.

    Args:
        config_paths: List of configuration file paths to validate

    Returns:
        List of valid configuration file paths
    """
    valid_paths = []

    for path in config_paths:
        file_path = Path(path)
        if file_path.exists() and file_path.is_file():
            valid_paths.append(path)
            logger.debug(f"Found configuration file: {path}")
        else:
            logger.warning(f"Configuration file not found: {path}")

    return valid_paths


def merge_configurations(
    config_paths: List[str],
) -> Optional[configparser.ConfigParser]:
    """
    Merge multiple configuration files into a single ConfigParser object.

    Args:
        config_paths: List of configuration file paths to merge

    Returns:
        Merged ConfigParser object or None if error occurs
    """
    config = configparser.ConfigParser()

    try:
        # Read configuration files in order (later files override earlier ones)
        files_read = config.read(config_paths)

        if not files_read:
            logger.error("No configuration files could be read")
            return None

        logger.debug(f"Successfully merged {len(files_read)} configuration file(s)")
        return config

    except (configparser.Error, IOError) as e:
        logger.error(f"Error reading configuration files: {e}")
        return None


def write_configuration(config: configparser.ConfigParser, output_path: str) -> bool:
    """
    Write the merged configuration to the output file.

    Args:
        config: ConfigParser object containing merged configuration
        output_path: Path where the merged configuration should be written

    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure the output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write the configuration
        with open(output_path, "w+") as fp:
            config.write(fp)

        logger.debug(f"Successfully wrote merged configuration to {output_path}")
        return True

    except IOError as e:
        logger.error(f"Error writing configuration file: {e}")
        return False


def main() -> None:
    """Main entry point for the configuration merger."""
    logger.debug("Starting Ansible configuration merge")

    # Define configuration files to merge (in order of precedence)
    config_paths = [DEFAULT_CONFIG_PATH, USER_CONFIG_PATH]

    # Validate configuration files
    valid_paths = validate_config_files(config_paths)

    if not valid_paths:
        logger.error("No valid configuration files found")
        sys.exit(1)

    # Merge configurations
    merged_config = merge_configurations(valid_paths)

    if merged_config is None:
        logger.error("Failed to merge configurations")
        sys.exit(1)

    # Write merged configuration
    if not write_configuration(merged_config, OUTPUT_CONFIG_PATH):
        logger.error("Failed to write merged configuration")
        sys.exit(1)

    logger.debug("Configuration merge completed successfully")


if __name__ == "__main__":
    main()
