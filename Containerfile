FROM python:3.12-alpine as builder

ARG VERSION

ARG USER_ID=45000
ARG GROUP_ID=45000

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV TZ=UTC

COPY --link files/ansible /ansible
COPY --link files/change-defaults.sh /change-defaults.sh
COPY --link files/change-generics.sh /change-generics.sh
COPY --link files/change-release.sh /change-release.sh
COPY --link files/change-osism.sh /change-osism.sh
COPY --link files/crontab /etc/crontabs/dragon
COPY --link files/entrypoint.sh /entrypoint.sh
COPY --link files/generate-inventory-from-netbox.py /generate-inventory-from-netbox.py
COPY --link files/handle-inventory-overwrite.py /handle-inventory-overwrite.py
COPY --link files/merge-ansible-cfg.py /merge-ansible-cfg.py
COPY --link files/prepare-vars.py /prepare-vars.py
COPY --link files/render-python-requirements.py /render-python-requirements.py
COPY --link files/requirements.txt /requirements.txt
COPY --link files/run.sh /run.sh
COPY --link files/sync-inventory-with-netbox.sh /sync-inventory-with-netbox.sh
COPY --link files/templates /templates

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

git clone --depth 1 https://github.com/osism/release /release
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
  /extra \
  /inventory \
  /inventory.merge \
  /inventory.pre \
  /opt/configuration \
  /state

chown -R dragon: \
  /defaults \
  /extra \
  /inventory \
  /inventory.generics \
  /inventory.merge \
  /inventory.pre \
  /opt/configuration \
  /state

apk del .build-deps

rm -f \
  /etc/crontabs/root \
  /render-python-requirements.py \
  /templates/requirements.txt.j2 \
  /requirements.extra.txt \
  /requirements.txt

EOF

USER dragon

FROM python:3.12-alpine

COPY --link --from=builder / /

USER dragon

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/entrypoint.sh"]
VOLUME ["/extra", "/inventory", "/inventory.pre", "/opt/configuration"]
