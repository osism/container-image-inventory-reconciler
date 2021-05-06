#!/usr/bin/env bash

printenv > /etc/environment

# NOTE: Really ugly. For whatever reason, the ansible-playbook running as
#       dragon wants to access /root. To store configuration files.
#       Setting ANSIBLE_DIRECTORY etc. does nothing.
chmod 777 /root
sudo su - dragon sh -c /run.sh

exec /usr/sbin/crond -f -d 8
