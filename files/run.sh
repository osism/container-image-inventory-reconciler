#!/usr/bin/env bash

source /etc/environment

rm -rf /inventory.pre/*

rsync -a --exclude README.md --exclude LICENSE --exclude '.*' /defaults/ /inventory.pre/group_vars/
rsync -a /inventory.generics/ /inventory.pre/
rsync -a /extra/ //inventory.pre/
rsync -a /opt/configuration/inventory/ /inventory.pre/

if [[ -e /run/secrets/NETBOX_TOKEN ]]; then
    python3 /generate-inventory-from-netbox.py
fi

python3 /handle-inventory-overwrite.py

cat /inventory.pre/[0-9]* > /inventory.pre/hosts
rm /inventory.pre/[0-9]*

rsync -a --delete --exclude .git /inventory.pre/ /inventory

pushd /inventory > /dev/null

if [[ ! -e .git ]]; then
    git init
    git config user.name "Inventory Reconciler"
    git config user.email "inventory@reconciler.local"

    git add -A
    git commit -m $(date +"%Y-%m-%d-%H-%M")
else
    git add -A
    git commit -m $(date +"%Y-%m-%d-%H-%M")
fi

popd > /dev/null
