# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
import sys

from loguru import logger

level = "INFO"
log_fmt = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)

logger.remove()
logger.add(sys.stdout, format=log_fmt, level=level, colorize=True)


def move_group_vars(dirname="/inventory.pre/group_vars/"):
    files = [f for f in os.listdir(dirname) if os.path.isfile(os.path.join(dirname, f))]
    for f in files:
        if f.endswith(".yml") or f.endswith(".yaml") or f.endswith("json"):
            d = Path(f).stem
            if os.path.isdir(os.path.join(dirname, d)):
                logger.info(f"Moving group_vars file {f} due to existing defaults")
                os.rename(os.path.join(dirname, f), os.path.join(dirname, d, f))


if __name__ == "__main__":
    move_group_vars("/inventory.pre/group_vars/")
