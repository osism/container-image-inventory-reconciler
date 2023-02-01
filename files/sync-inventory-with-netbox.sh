#!/usr/bin/env bash

if [[ -e /etc/environment ]]; then
    source /etc/environment
fi

export NETBOX_API

flock -n /tmp/sync-inventory-with-netbox.lock -c 'ansible-playbook -i /inventory /ansible/playbooks/import-netbox.yml'
