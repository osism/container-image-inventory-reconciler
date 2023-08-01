#!/usr/bin/env python3

import configparser
import os

config = configparser.ConfigParser()
config.read(["/defaults/ansible.cfg", "/opt/configuration/environments/ansible.cfg"])

with open("/inventory/ansible/ansible.cfg", "w+") as fp:
    config.write(fp)
