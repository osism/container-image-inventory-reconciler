#!/usr/bin/env bash

source /etc/environment

rm -rf /inventory.pre/*

ls -1 /opt/configuration/inventory/

rsync -a --exclude README.md --exclude LICENSE --exclude '.*' /defaults/ /inventory.pre/group_vars/
rsync -a /inventory.generics/ /inventory.pre/
rsync -a /extra/ //inventory.pre/
rsync -a /opt/configuration/inventory/ /inventory.pre/

# get version files from /interface/versions
cp /interface/versions/osism-ansible.yml /inventory.pre/group_vars/all/100-versions-osism-ansible.yml
if [[ -e /interface/versions/ceph-ansible.yml ]]; then
    cp /interface/versions/ceph-ansible.yml /inventory.pre/group_vars/all/100-versions-ceph-ansible.yml
fi
if [[ -e /interface/versions/kolla-ansible.yml ]]; then
    cp /interface/versions/kolla-ansible.yml /inventory.pre/group_vars/all/100-versions-kolla-ansible.yml
fi

# get overlay files from /interface/overlays
cp /interface/overlays/kolla-ansible.yml /inventory.pre/group_vars/all/100-overlays-kolla-ansible.yml

if [[ -e /run/secrets/NETBOX_TOKEN ]]; then
    python3 /generate-inventory-from-netbox.py
fi

python3 /handle-inventory-overwrite.py

# NOTE: The intermediate step via the inventory.merge directory
#       is necessary to remove other files in /inventory via -delete.
ansible-inventory -i /inventory.pre --list -y --output /inventory.merge/hosts.yml
rsync -a --delete --exclude .git /inventory.merge/ /inventory

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
