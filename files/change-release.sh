#!/usr/bin/env bash

rm -rf /release
git clone --depth 1 -b $1 https://github.com/osism/release /release
