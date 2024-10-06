# SPDX-License-Identifier: Apache-2.0

# This script reads two files in the /inventory.pre directory (if it exists)
# and merges it in a new file in /inventory.pre.

import configparser
import os
import sys

from loguru import logger

level = "INFO"
log_fmt = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)

logger.remove()
logger.add(sys.stdout, format=log_fmt, level=level, colorize=True)


def merge_inventory_files(source1, source2, target, dirname="/inventory.pre/"):
    if not os.path.isfile(os.path.join(dirname, source1)):
        logger.info(f"File {source1} not found in {dirname}")
        return

    if not os.path.isfile(os.path.join(dirname, source2)):
        logger.info(f"File {source2} not found in {dirname}")
        return

    logger.info(f"Merging {source1} and {source2} in {target}")

    try:
        config1 = configparser.ConfigParser(allow_no_value=True, delimiters="😈")
        config1.read(os.path.join(dirname, source1))
    except UnicodeDecodeError as e:
        logger.error(f"Syntax issue in file {source1}: {e}")
        return

    try:
        config2 = configparser.ConfigParser(allow_no_value=True, delimiters="😈")
        config2.read(os.path.join(dirname, source2))
    except UnicodeDecodeError as e:
        logger.error(f"Syntax issue in file {source2}: {e}")
        return

    for section in config2.sections():
        if not config1.has_section(section):
            config1.add_section(section)
        for key, value in config2.items(section):
            config1.set(section, key)

    os.remove(os.path.join(dirname, source1))
    os.remove(os.path.join(dirname, source2))

    with open(os.path.join(dirname, target), "w+") as fp:
        config1.write(fp)


if __name__ == "__main__":
    merge_inventory_files("20-roles", "20-netbox", "20-roles")
