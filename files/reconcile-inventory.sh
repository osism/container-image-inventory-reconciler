#!/usr/bin/env bash

rsync -a --delete --exclude=".*" /defaults/ /inventory/group_vars/
rsync -a --delete /inventory.generics/ /inventory/
rsync -a --delete /configuration/inventory/ /inventory/

python3 /handle-inventory-overwrite.py

cat /inventory/[0-9]* > /inventory/hosts
rm /inventory/[0-9]*
