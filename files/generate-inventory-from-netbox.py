#!/usr/bin/env python3

# This script reads all required systems from the Netbox and writes them
# into a form that can be evaluated by the Ansible Inventory Plugin INI. 
#
# This is a workaround to use the groups defined in cfg-generics without
# having to import them into Netbox.

import os

import pynetbox


# Read secret from file
def read_secret(secret_name):
    try:
        f = open('/run/secrets/' + secret_name, 'r', encoding='utf-8')
    except EnvironmentError:
        return ''
    else:
        with f:
            return f.readline().strip()


NETBOX_URL = os.getenv("NETBOX_API")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", read_secret("NETBOX_TOKEN"))
IGNORE_SSL_ERRORS = (os.getenv("IGNORE_SSL_ERRORS", "True") == "True")

nb = pynetbox.api(
    NETBOX_URL,
    NETBOX_TOKEN
)

if IGNORE_SSL_ERRORS:
    import requests
    requests.packages.urllib3.disable_warnings()
    session = requests.Session()
    session.verify = False
    nb.http_session = session

devices = nb.dcim.devices.filter(
    tag=["managed-by-bifrost", "managed-by-osism"],
    status="active",
    cf_device_type=["server"],
    cf_provisioning_state=["active"]
)

devices_to_tags = {}

for device in devices:
    for tag in device.tags:
        if not tag.slug in devices_to_tags:
            devices_to_tags[tag.slug] = []
        devices_to_tags[tag.slug].append(device)

data = {
    "devices_to_tags": devices_to_tags
}

loader = jinja2.FileSystemLoader(searchpath="/templates/")
environment = jinja2.Environment(loader=loader)
template = environment.get_template("netbox.hosts.j2")
result = template.render(data)

with open(f"/inventory.pre/netbox.hosts", "w+") as fp:
    fp.write(os.linesep.join([s for s in result.splitlines() if s]))

for tag in devices_to_tags:
    print(f"[{tag}]")

    for device in devices_to_tags[tag]:
        print(f"{device}")

    print("\n")
