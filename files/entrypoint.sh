#!/usr/bin/env bash

CELERY=${CELERY:-0}

/run.sh

if [[ "${CELERY}" == 0 ]]; then
    exec /usr/sbin/crond -f -d 8
elif [[ "${CELERY}" == 1 ]]; then
    exec osism reconciler
fi
