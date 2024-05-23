#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import configparser

config = configparser.ConfigParser()
config.read(["/defaults/ansible.cfg", "/opt/configuration/environments/ansible.cfg"])

with open("/inventory/ansible/ansible.cfg", "w+") as fp:
    config.write(fp)
