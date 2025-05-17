# SPDX-License-Identifier: Apache-2.0

"""
Move Ansible group_vars files to their appropriate subdirectories.

This script reorganizes Ansible group_vars files when there are existing
directory structures. If a YAML or JSON file exists in the group_vars directory
with the same name as an existing subdirectory, the file is moved into that
subdirectory to follow Ansible's group_vars organization conventions.
"""

import os
import sys
from pathlib import Path
from typing import List, Set

from loguru import logger

# Constants
DEFAULT_GROUP_VARS_DIR = "/inventory.pre/group_vars/"
SUPPORTED_EXTENSIONS = {".yml", ".yaml", ".json"}

# Logger configuration
LOGGER_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)
logger.remove()
logger.add(sys.stdout, format=LOGGER_FORMAT, level="INFO", colorize=True)


def validate_directory(dir_path: str) -> bool:
    """
    Validate that the directory exists and is accessible.

    Args:
        dir_path: Path to the directory to validate

    Returns:
        True if directory exists and is accessible, False otherwise
    """
    try:
        path = Path(dir_path)
        if not path.exists():
            logger.error(f"Directory does not exist: {dir_path}")
            return False

        if not path.is_dir():
            logger.error(f"Path is not a directory: {dir_path}")
            return False

        # Check if directory is readable
        if not os.access(dir_path, os.R_OK):
            logger.error(f"Directory is not readable: {dir_path}")
            return False

        return True

    except (OSError, IOError) as e:
        logger.error(f"Error accessing directory {dir_path}: {e}")
        return False


def get_group_vars_files(dirname: str) -> List[Path]:
    """
    Get all group_vars files with supported extensions from the directory.

    Args:
        dirname: Directory to scan for group_vars files

    Returns:
        List of Path objects for valid group_vars files
    """
    group_vars_files = []

    try:
        for item in os.listdir(dirname):
            item_path = Path(dirname) / item

            if item_path.is_file() and item_path.suffix in SUPPORTED_EXTENSIONS:
                group_vars_files.append(item_path)
                logger.debug(f"Found group_vars file: {item}")

    except (OSError, IOError) as e:
        logger.error(f"Error listing directory {dirname}: {e}")

    return group_vars_files


def get_existing_directories(dirname: str) -> Set[str]:
    """
    Get all existing subdirectories in the group_vars directory.

    Args:
        dirname: Directory to scan for subdirectories

    Returns:
        Set of subdirectory names
    """
    subdirectories = set()

    try:
        for item in os.listdir(dirname):
            item_path = Path(dirname) / item

            if item_path.is_dir():
                subdirectories.add(item)
                logger.debug(f"Found subdirectory: {item}")

    except (OSError, IOError) as e:
        logger.error(f"Error scanning for directories in {dirname}: {e}")

    return subdirectories


def move_file_to_directory(source_file: Path, target_dir: Path) -> bool:
    """
    Move a file to the specified directory.

    Args:
        source_file: Path to the file to move
        target_dir: Target directory path

    Returns:
        True if successful, False otherwise
    """
    try:
        target_path = target_dir / source_file.name

        # Check if target already exists
        if target_path.exists():
            logger.warning(f"Target file already exists: {target_path}")
            return False

        # Move the file
        source_file.rename(target_path)
        logger.info(f"Moved {source_file.name} to {target_dir.name}/")
        return True

    except (OSError, IOError) as e:
        logger.error(f"Error moving file {source_file}: {e}")
        return False


def move_group_vars(dirname: str = DEFAULT_GROUP_VARS_DIR) -> None:
    """
    Move group_vars files to their appropriate subdirectories.

    Args:
        dirname: Path to the group_vars directory
    """
    # Validate directory
    if not validate_directory(dirname):
        logger.error("Cannot proceed with invalid directory")
        return

    logger.debug(f"Processing group_vars directory: {dirname}")

    # Get files and directories
    group_vars_files = get_group_vars_files(dirname)
    existing_directories = get_existing_directories(dirname)

    if not group_vars_files:
        logger.debug("No group_vars files found to process")
        return

    if not existing_directories:
        logger.debug("No subdirectories found - no files need to be moved")
        return

    # Process each file
    moved_count = 0
    for file_path in group_vars_files:
        file_stem = file_path.stem

        # Check if a corresponding directory exists
        if file_stem in existing_directories:
            logger.debug(f"Found matching directory for {file_path.name}")
            target_dir = Path(dirname) / file_stem

            if move_file_to_directory(file_path, target_dir):
                moved_count += 1
        else:
            logger.debug(f"No matching directory for {file_path.name}")

    logger.info(f"Moved {moved_count} file(s) to their respective directories")


def main() -> None:
    """Main entry point for the group_vars mover script."""
    logger.info("Starting group_vars file reorganization")

    # Use default directory or get from command line
    group_vars_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GROUP_VARS_DIR

    move_group_vars(group_vars_dir)

    logger.info("Group_vars file reorganization completed")


if __name__ == "__main__":
    main()
