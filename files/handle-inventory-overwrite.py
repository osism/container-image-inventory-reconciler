# SPDX-License-Identifier: Apache-2.0

"""
This script reads a file in the /inventory.pre directory (if it exists).

Then it reads all other files (with exception of 99-overwrite) in /inventory.pre
and removes from them all sections that are present in the file. It considers
the variant with :children and without.

With this approach it is possible to overwrite all group definitions from
existing files with exception of 99-overwrite.
"""

import configparser
import os
import sys
from pathlib import Path
from typing import List, Set

from loguru import logger

# Constants
DEFAULT_INVENTORY_DIR = "/inventory.pre/"
INVENTORY_DELIMITERS = "😈"
CHILDREN_SUFFIX = ":children"
EXCLUDED_FILES = {"20-roles", "20-netbox", "99-overwrite"}
EXCLUDED_EXTENSIONS = {".yml", ".yaml"}

# Logger configuration
LOGGER_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)
logger.remove()
logger.add(sys.stdout, format=LOGGER_FORMAT, level="INFO", colorize=True)


def get_section_variants(section: str) -> List[str]:
    """
    Get all variants of a section name (with and without :children suffix).

    Args:
        section: The base section name

    Returns:
        List of section name variants
    """
    if section.endswith(CHILDREN_SUFFIX):
        base_section = section[: -len(CHILDREN_SUFFIX)]
        return [base_section, section]
    else:
        return [section, f"{section}{CHILDREN_SUFFIX}"]


def read_config_file(filepath: Path) -> configparser.ConfigParser:
    """
    Read a configuration file with proper error handling.

    Args:
        filepath: Path to the configuration file

    Returns:
        ConfigParser object if successful, None otherwise
    """
    config = configparser.ConfigParser(
        allow_no_value=True, delimiters=INVENTORY_DELIMITERS
    )
    try:
        config.read(filepath)
        return config
    except UnicodeDecodeError as e:
        logger.error(f"Syntax issue in file {filepath.name}: {e}")
        return None


def collect_sections_to_remove(config: configparser.ConfigParser) -> Set[str]:
    """
    Collect all sections and their variants from the configuration.

    Args:
        config: ConfigParser object containing the sections

    Returns:
        Set of all section names to remove (including variants)
    """
    sections = set()
    for section in config.sections():
        sections.update(get_section_variants(section))
    return sections


def should_process_file(file_entry: os.DirEntry, exclude_filename: str) -> bool:
    """
    Determine if a file should be processed for section removal.

    Args:
        file_entry: Directory entry for the file
        exclude_filename: Name of the file being handled

    Returns:
        True if file should be processed, False otherwise
    """
    if not file_entry.is_file():
        return False

    file_path = Path(file_entry.path)
    filename = file_path.name

    # Check if it's the file we're handling
    if filename == exclude_filename:
        return False

    # Check excluded files
    if file_path.stem in EXCLUDED_FILES:
        return False

    # Check hidden files
    if filename.startswith("."):
        return False

    # Check excluded extensions
    if file_path.suffix in EXCLUDED_EXTENSIONS:
        return False

    return True


def remove_sections_from_file(file_path: Path, sections_to_remove: Set[str]) -> int:
    """
    Remove specified sections from a file.

    Args:
        file_path: Path to the file to process
        sections_to_remove: Set of section names to remove

    Returns:
        Number of sections removed
    """
    config = read_config_file(file_path)
    if config is None:
        return 0

    changed = False
    removed_count = 0
    for section in sections_to_remove:
        if config.remove_section(section):
            logger.info(f"Removing group {section} from {file_path.name}")
            changed = True
            removed_count += 1

    if changed:
        with open(file_path, "w") as fp:
            config.write(fp)

    return removed_count


def handle_overwrite_file(filename: str, dirname: str = DEFAULT_INVENTORY_DIR) -> int:
    """
    Handle group overwrites from a specific file.

    Args:
        filename: Name of the file containing sections to overwrite
        dirname: Directory containing the inventory files

    Returns:
        Total number of groups removed
    """
    file_path = Path(dirname) / filename

    if not file_path.is_file():
        return 0

    logger.info(f"Handling group overwrites in {filename}")

    # Read the source file
    source_config = read_config_file(file_path)
    if source_config is None:
        return 0

    # Collect all sections to remove
    sections_to_remove = collect_sections_to_remove(source_config)

    # Process all other files in the directory
    total_removed = 0
    for file_entry in os.scandir(dirname):
        if should_process_file(file_entry, filename):
            removed = remove_sections_from_file(
                Path(file_entry.path), sections_to_remove
            )
            total_removed += removed

    return total_removed


def main() -> None:
    """Main entry point for the script."""
    logger.info("Starting inventory overwrite handling")

    total_changed_groups = 0

    # Handle each overwrite file
    changed = handle_overwrite_file("99-overwrite")
    total_changed_groups += changed

    changed = handle_overwrite_file("20-netbox")
    total_changed_groups += changed

    changed = handle_overwrite_file("20-roles")
    total_changed_groups += changed

    logger.info(f"Removed {total_changed_groups} group(s) in total")
    logger.info("Inventory overwrite handling completed")


if __name__ == "__main__":
    main()
