#!/usr/bin/env bash

if [[ ! -e /usr/bin/git ]]; then
  apt-get update \
    && apt-get install --no-install-recommends -y git
fi

if [[ "$1" == "defaults" ]]; then
    rm -rf /defaults
    git clone --depth 1 -b $2 https://github.com/osism/defaults /defaults
elif [[ "$1" == "generics" ]]; then
    rm -rf /generics
    git clone --depth 1 -b $2 https://github.com/osism/cfg-generics /generics

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
elif [[ "$1" == "osism" ]]; then
    rm -rf /python-osism
    git clone --depth 1 -b $2 https://github.com/osism/python-osism /python-osism

    pushd /python-osism
    pip3 uninstall -y osism
    python3 -m pip --no-cache-dir install -U /python-osism
    popd
elif [[ "$1" == "release" ]]; then
    rm -rf /release
    git clone --depth 1 -b $2 https://github.com/osism/release /release
fi

chown -R dragon: \
    /defaults \
    /extra \
    /inventory \
    /inventory.generics \
    /inventory.merge \
    /inventory.pre

su -c bash /run.sh dragon
