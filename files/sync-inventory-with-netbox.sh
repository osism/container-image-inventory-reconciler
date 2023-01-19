#!/usr/bin/env bash

source /etc/environment
export NETBOX_API

# NOTE: locking inspired by https://www.baeldung.com/linux/bash-ensure-instance-running

LOCK_FILE=/tmp/sync-inventory-with-netbox.lock
LOCK_TIMEOUT=300

remove_lock()
{
    rm -f "$LOCK_FILE"
}

another_instance()
{
    echo "There is another instance running, exiting"
    exit 1
}

lockfile -r 0 -l $LOCK_TIMEOUT "$LOCK_FILE" || another_instance
trap remove_lock EXIT

ansible-playbook -i /inventory /ansible/playbooks/import-netbox.yml
