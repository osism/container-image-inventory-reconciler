#!/usr/bin/env bash

source /etc/environment
export NETBOX_API

flock -n /tmp/sync-inventory-with-netbox.lock -c 'ansible-playbook -i /inventory /ansible/playbooks/import-netbox.yml'
