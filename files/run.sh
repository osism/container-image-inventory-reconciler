#!/usr/bin/env bash

rm -rf /inventor.pre/*

rsync -a --exclude README.md --exclude LICENSE --exclude '.*' /defaults/ /inventory.pre/group_vars/
rsync -a /inventory.generics/ /inventory.pre/
rsync -a /extra/ /extra/
rsync -a /opt/configuration/inventory/ /inventory.pre/

python3 /handle-inventory-overwrite.py

cat /inventory.pre/[0-9]* > /inventory.pre/hosts
rm /inventory.pre/[0-9]*

rsync -a --delete --exclude .git /inventory.pre/ /inventory

pushd /inventory

if [[ ! -e .git ]]; then
    git init
    git config user.name "Inventory Reconciler"
    git config user.email "inventory@reconciler.local"
fi

git add -A
git commit -m $(date +"%Y-%m-%d-%H-%M")

popd
