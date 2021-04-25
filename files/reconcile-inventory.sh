#!/usr/bin/env bash

rsync -a --exclude=".*" /defaults/ /inventory/group_vars/
rsync -a /inventory.generics/ /inventory/
rsync -a /configuration/inventory/ /inventory/

python3 /handle-inventory-overwrite.py

cat /inventory/[0-9]* > /inventory/hosts
rm /inventory/[0-9]*
