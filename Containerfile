FROM python:3.11-alpine

ARG VERSION

ARG USER_ID=45000
ARG GROUP_ID=45000

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV TZ=UTC

COPY files/ansible /ansible
COPY files/crontab /etc/crontabs/dragon
COPY files/entrypoint.sh /entrypoint.sh
COPY files/generate-inventory-from-netbox.py /generate-inventory-from-netbox.py
COPY files/handle-inventory-overwrite.py /handle-inventory-overwrite.py
COPY files/merge-ansible-cfg.py /merge-ansible-cfg.py
COPY files/render-python-requirements.py /render-python-requirements.py
COPY files/requirements.txt /requirements.txt
COPY files/run.sh /run.sh
COPY files/sync-inventory-with-netbox.sh /sync-inventory-with-netbox.sh
COPY files/templates /templates

# hadolint ignore=DL3003
RUN <<EOF
set -e
set -x

apk add --no-cache \
  bash \
  git \
  jq \
  rsync \
  sudo \
  tini
apk add --no-cache --virtual .build-deps \
  build-base \
  libffi-dev \
  openssl-dev \
  python3-dev

pip3 install --no-cache-dir --upgrade pip
pip3 install --no-cache-dir -r /requirements.txt

git clone https://github.com/osism/release /release
python3 /render-python-requirements.py
pip3 install --no-cache-dir -r /requirements.extra.txt

git clone https://github.com/osism/defaults /defaults
( cd /defaults || exit; git fetch --all --force; git checkout "$(yq -M -r .defaults_version "/release/$VERSION/base.yml")" )

git clone https://github.com/osism/cfg-generics /generics
( cd /generics || exit; git fetch --all --force; git checkout "$(yq -M -r .generics_version "/release/$VERSION/base.yml")" )

mkdir -p /inventory.generics/
cp /generics/inventory/50-ceph /inventory.generics/50-ceph
cp /generics/inventory/50-infrastruture /inventory.generics/50-infrastruture
cp /generics/inventory/50-kolla /inventory.generics/50-kolla
cp /generics/inventory/50-monitoring /inventory.generics/50-monitoring
cp /generics/inventory/50-openstack /inventory.generics/50-openstack
cp /generics/inventory/51-ceph /inventory.generics/51-ceph
cp /generics/inventory/51-kolla /inventory.generics/51-kolla
cp /generics/inventory/60-generic /inventory.generics/60-generic

ansible-galaxy collection install -v -f -r /ansible/requirements.yml -p /usr/share/ansible/collections
ln -s /usr/share/ansible/collections /ansible/collections

adduser -D inventory-reconciler

addgroup -g $GROUP_ID dragon
adduser -D -u $USER_ID -G dragon dragon

mkdir -p \
  /inventory \
  /inventory.pre \
  /inventory.merge \
  /opt/configuration \
  /extra

chown -R dragon: \
  /defaults \
  /inventory \
  /inventory.pre \
  /inventory.merge \
  /inventory.generics \
  /opt/configuration \
  /extra

apk del .build-deps

rm /etc/crontabs/root
rm /render-python-requirements.py
rm /templates/requirements.txt.j2
rm /requirements.extra.txt
rm /requirements.txt

EOF

USER dragon

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/entrypoint.sh"]

VOLUME /extra
VOLUME /inventory
VOLUME /inventory.pre
VOLUME /opt/configuration
