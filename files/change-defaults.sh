#!/usr/bin/env bash

rm -rf /defaults
git clone --depth 1 -b $1 https://github.com/osism/defaults /defaults
