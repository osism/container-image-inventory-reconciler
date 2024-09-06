#!/usr/bin/env bash

set -e

ON_CHANGE=${ON_CHANGE:-0}

if [[ -e /etc/environment ]]; then
    source /etc/environment
fi

# Ignore the following warning message:
#
# [WARNING]: Invalid characters were found in group names but not replaced, use
# -vvvv to see details
export ANSIBLE_TRANSFORM_INVALID_GROUP_CHARS=ignore

# If the reconciler should only run on changes to /opt/configuration it is
# checked here first and stopped if necessary.
if [[ $ON_CHANGE == 1 && -e /state/last_change ]]; then
    if [[ $(cat /state/last_change) == $(git --git-dir=/opt/configuration/.git rev-parse --short HEAD) ]]; then
        echo "No change detected in /opt/configuration since last run. Exit."
        exit 0
    fi
fi

rm -rf /inventory.pre/*

rsync -q -a --exclude README.md --exclude LICENSE --exclude '.*' /defaults/ /inventory.pre/group_vars/
rsync -q -a /inventory.generics/ /inventory.pre/
rsync -q -a /extra/ /inventory.pre/
rsync -q -a --exclude '.*' /opt/configuration/inventory/ /inventory.pre/

# get version files from /interface/versions
if [[ -e /interface/versions/osism-ansible.yml ]]; then
    cp /interface/versions/osism-ansible.yml /inventory.pre/group_vars/all/100-versions-osism-ansible.yml
fi
if [[ -e /interface/versions/ceph-ansible.yml ]]; then
    cp /interface/versions/ceph-ansible.yml /inventory.pre/group_vars/all/100-versions-ceph-ansible.yml
fi
if [[ -e /interface/versions/kolla-ansible.yml ]]; then
    cp /interface/versions/kolla-ansible.yml /inventory.pre/group_vars/all/100-versions-kolla-ansible.yml
fi

# get overlay files from /interface/overlays
if [[ -e /interface/overlays/kolla-ansible.yml ]]; then
    cp /interface/overlays/kolla-ansible.yml /inventory.pre/group_vars/all/100-overlays-kolla-ansible.yml
fi

if [[ -e /interface/overlays/release-kolla-ansible.yml ]]; then
    cp /interface/overlays/release-kolla-ansible.yml /inventory.pre/group_vars/all/100-overlays-release-kolla-ansible.yml
fi

if [[ -e /run/secrets/NETBOX_TOKEN && ! -z "$(cat /run/secrets/NETBOX_TOKEN)" && $INVENTORY_FROM_NETBOX == "True" ]]; then
    python3 /generate-inventory-from-netbox.py
fi

python3 /prepare-vars.py

python3 /handle-inventory-overwrite.py
if [[ -e /inventory.pre/99-overwrite ]]; then
    mv /inventory.pre/99-overwrite /inventory.pre/49-overwrite
fi

# The intermediate step via the inventory.merge directory
# is necessary to remove other files in /inventory via -delete.
ansible-inventory -i /inventory.pre --list -y --output /inventory.merge/hosts.yml
rsync -q -a --delete --exclude .git /inventory.merge/ /inventory

pushd /inventory > /dev/null || exit 1

# check if we are in a git repository
if git -C . rev-parse 2> /dev/null ; then
    git init
    git config user.name "Inventory Reconciler"
    git config user.email "inventory@reconciler.local"
elif [[ -z "$(git config --get user.name)"  ]]; then
    git config user.name "Inventory Reconciler"
elif [[ -z "$(git config --get user.email)"  ]]; then
    git config user.email "inventory@reconciler.local"
fi

if [[ $(git status --porcelain --untracked-files=no | wc -l) != 0 || ! -e /inventory/clustershell ]]; then
    mkdir -p /inventory/clustershell
    python3 /generate-clustershell-ansible-file.py
fi

mkdir -p /inventory/ansible
python3 /merge-ansible-cfg.py

if [[ $(git status --porcelain) ]]; then
    git add -A
    git commit -m $(date +"%Y-%m-%d-%H-%M")

    if [[ $ON_CHANGE == 1 ]]; then
        git --git-dir=/opt/configuration/.git rev-parse --short HEAD > /state/last_change
    fi
fi

popd > /dev/null
