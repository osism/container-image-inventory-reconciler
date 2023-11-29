#!/usr/bin/env bash

rm -rf /generics
git clone --depth 1 -b $1 https://github.com/osism/generics /generics

rm -rf /inventory.generics/
mkdir -p /inventory.generics/
cp /generics/inventory/50-ceph /inventory.generics/50-ceph
cp /generics/inventory/50-infrastruture /inventory.generics/50-infrastruture
cp /generics/inventory/50-kolla /inventory.generics/50-kolla
cp /generics/inventory/50-monitoring /inventory.generics/50-monitoring
cp /generics/inventory/50-openstack /inventory.generics/50-openstack
cp /generics/inventory/51-ceph /inventory.generics/51-ceph
cp /generics/inventory/51-kolla /inventory.generics/51-kolla
cp /generics/inventory/60-generic /inventory.generics/60-generic
