#!/usr/bin/env bash

printenv > /etc/environment

CELERY=${CELERY:-0}

# NOTE: Really ugly. For whatever reason, the ansible-playbook running as
#       dragon wants to access /root. To store configuration files.
#       Setting ANSIBLE_DIRECTORY etc. does nothing.
chmod 777 /root
sudo su - dragon sh -c /run.sh

if [[ "${CELERY}" == 0 ]]; then
    exec /usr/sbin/crond -f -d 8
elif [[ "${CELERY}" == 1 ]]; then
    exec osism reconciler
fi
