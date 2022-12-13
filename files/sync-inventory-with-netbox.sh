#!/usr/bin/env bash

source /etc/environment
export NETBOX_API

if [[ -e /run/secrets/NETBOX_TOKEN ]]; then
    flock -n /tmp/sync-inventory-with-netbox.lock -c 'ansible-playbook -i /inventory /ansible/playbooks/import-netbox.yml'
fi
