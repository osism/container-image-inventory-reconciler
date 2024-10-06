# SPDX-License-Identifier: Apache-2.0

# This script reads a file in the /inventory.pre directory (if it exists).
#
# Then it reads all other files (with exception of 99-overwrite) in /inventory.pre
# and removes from them all sections that are present in the file. It considers
# the variant with :children and without.
#
# With this approach it is possible to overwrite all group definitions from
# existing files with exception of 99-overwrite.

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


def handle_overwrite_file(filename, dirname="/inventory.pre/"):
    if not os.path.isfile(os.path.join(dirname, filename)):
        return

    logger.info(f"Handling group overwrites in {filename}")

    try:
        config = configparser.ConfigParser(allow_no_value=True, delimiters="😈")
        config.read(os.path.join(dirname, filename))
    except UnicodeDecodeError as e:
        logger.error(f"Syntax issue in file {filename}: {e}")
        return

    sections = []

    for section in config.sections():
        if section.endswith(":children"):
            sections.append(section[:-9])
        else:
            sections.append("%s:children" % section)

        sections.append(section)

    for f in os.scandir(dirname):
        if (
            f.is_file()
            and not f.path.endswith(filename)
            and not f.path.endswith("20-roles")
            and not f.path.endswith("20-netbox")
            and not f.path.endswith("99-overwrite")
            and not f.name.startswith(".")
            and not f.name.endswith(".yml")
            and not f.name.endswith(".yaml")
        ):
            changed = False

            config = configparser.ConfigParser(allow_no_value=True, delimiters="😈")

            try:
                config.read(os.path.join(f))
            except UnicodeDecodeError as e:
                logger.error(f"Syntax issue in file {f.name}: {e}")
                return

            for section in sections:
                if config.remove_section(section):
                    logger.info(f"Removing group {section} from {f.name}")
                    changed = True

            if changed:
                with open(f, "w") as fp:
                    config.write(fp)


if __name__ == "__main__":
    handle_overwrite_file("99-overwrite")
    handle_overwrite_file("20-netbox")
    handle_overwrite_file("20-roles")
