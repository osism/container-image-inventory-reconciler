#!/usr/bin/env bash

sudo -iu dragon sh -c /run.sh

exec /usr/sbin/crond -f -d 8
