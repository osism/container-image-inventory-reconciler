#!/usr/bin/env bash

rm -rf /src
git clone --depth 1 -b $1 https://github.com/osism/python-osism /src

pushd /src
pip3 uninstall -y osism
python3 -m pip --no-cache-dir install -U /src
popd
