# SPDX-License-Identifier: Apache-2.0

import subprocess
import sys

from loguru import logger
import yaml

level = "INFO"
log_fmt = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)

logger.remove()
logger.add(sys.stdout, format=log_fmt, level=level, colorize=True)

subprocess.run(
    "ansible -i /inventory/hosts.yml -m ansible.builtin.template -a 'src=/templates/clustershell.yml.j2 dest=/inventory/clustershell/ansible.yaml mode=0644' localhost",
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

with open("/inventory/clustershell/ansible.yaml", "r") as fp:
    data = yaml.load(fp, Loader=yaml.FullLoader)

for group in data["ansible"]:
    unsorted = data["ansible"][group]
    data["ansible"][group] = sorted(unsorted)

logger.info("Writing /inventory/clustershell/ansible.yaml with clustershell groups")
with open("/inventory/clustershell/ansible.yaml", "w+") as fp:
    fp.write(yaml.dump(data))
