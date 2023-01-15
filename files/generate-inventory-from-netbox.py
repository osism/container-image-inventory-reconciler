#!/usr/bin/env python3

# This script reads all required systems from the Netbox and writes them
# into a form that can be evaluated by the Ansible Inventory Plugin INI.
#
# This is a workaround to use the groups defined in cfg-generics without
# having to import them into Netbox.

import os
import sys
import time

import jinja2
import pynetbox


# Read secret from file
def read_secret(secret_name):
    try:
        f = open("/run/secrets/" + secret_name, "r", encoding="utf-8")
    except EnvironmentError:
        return ""
    else:
        with f:
            return f.readline().strip()


NETBOX_URL = os.getenv("NETBOX_API")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", read_secret("NETBOX_TOKEN"))
IGNORE_SSL_ERRORS = os.getenv("IGNORE_SSL_ERRORS", "True") == "True"

# After a restart of the container, the Netbox is not directly
# accessible. Therefore up to 10 attempts until the Netbox is
# reachable.
for i in range(10):
    try:
        nb = pynetbox.api(NETBOX_URL, NETBOX_TOKEN)

        if IGNORE_SSL_ERRORS:
            import requests

            requests.packages.urllib3.disable_warnings()
            session = requests.Session()
            session.verify = False
            nb.http_session = session

        # Do something to check the connection
        nb.dcim.sites.count()
    except:
        time.sleep(1)
    else:
        break
else:
    sys.exit(1)

devices = nb.dcim.devices.filter(
    tag=["managed-by-osism"],
    status="active",
    cf_deployment_enabled=[True],
    cf_deployment_type=["osism"],
    cf_device_type=["server"],
    cf_maintenance=[False],
    cf_provision_state=["active"],
)

devices_to_tags = {}

for device in devices:
    for tag in [
        x
        for x in device.tags
        if x.slug not in ["managed-by-osism", "managed-by-ironic"]
    ]:
        if not tag.slug in devices_to_tags:
            devices_to_tags[tag.slug] = []
        devices_to_tags[tag.slug].append(device)

data = {"devices_to_tags": devices_to_tags}

loader = jinja2.FileSystemLoader(searchpath="/templates/")
environment = jinja2.Environment(loader=loader)
template = environment.get_template("netbox.hosts.j2")
result = template.render(data)

with open(f"/inventory.pre/99-netbox", "w+") as fp:
    fp.write(os.linesep.join([s for s in result.splitlines() if s]))
