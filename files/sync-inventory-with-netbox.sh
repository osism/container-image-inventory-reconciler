#!/usr/bin/env bash

source /etc/environment
export NETBOX_API

if [[ -e /run/secrets/NETBOX_TOKEN ]]; then
    ansible-playbook -i /inventory /ansible/playbooks/import-netbox.yml
fi
