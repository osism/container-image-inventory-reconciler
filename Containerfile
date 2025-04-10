FROM python:3.13-alpine AS builder

ARG VERSION

ARG USER_ID=45000
ARG GROUP_ID=45000

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV TZ=UTC

# This solves the following problem. It can be removed in the future if
# netifaces is no longer used as a dependency of the OpenStack SDK.
#
# netifaces.c:1808:9: error: initialization of 'int' from 'void *' makes
# integer from pointer without a cast [-Wint-conversion]
ENV CFLAGS="-Wno-int-conversion"

COPY --link files/ansible /ansible
COPY --link files/change.sh /change.sh
COPY --link files/crontab /etc/crontabs/dragon
COPY --link files/entrypoint.sh /entrypoint.sh
COPY --link files/generate-clustershell-ansible-file.py /generate-clustershell-ansible-file.py
COPY --link files/generate-inventory-from-netbox.py /generate-inventory-from-netbox.py
COPY --link files/handle-inventory-overwrite.py /handle-inventory-overwrite.py
COPY --link files/merge-ansible-cfg.py /merge-ansible-cfg.py
COPY --link files/merge-inventory-files.py /merge-inventory-files.py
COPY --link files/move-group-vars.py /move-group-vars.py
COPY --link files/prepare-vars.py /prepare-vars.py
COPY --link files/render-python-requirements.py /render-python-requirements.py
COPY --link files/requirements.txt /requirements.txt
COPY --link files/run.sh /run.sh
COPY --link files/sync-inventory-with-netbox.sh /sync-inventory-with-netbox.sh
COPY --link files/templates /templates

COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /usr/local/bin/uv

RUN <<EOF
set -e
set -x

apk add --no-cache \
  bash \
  git \
  jq \
  rsync \
  tini
apk add --no-cache --virtual .build-deps \
  build-base \
  libffi-dev \
  openssl-dev \
  python3-dev

uv pip install --no-cache --system -r /requirements.txt

git clone https://github.com/osism/release /release
git clone https://github.com/osism/defaults /defaults
git clone https://github.com/osism/cfg-generics /generics

if [ "$VERSION" != "latest" ]; then
  ( cd /release || exit; git fetch --all --force; git checkout "inventory-reconciler-$VERSION" )
  ( cd /defaults || exit; git fetch --all --force; git checkout "$(yq -M -r .defaults_version "/release/latest/base.yml")" )
  ( cd /generics || exit; git fetch --all --force; git checkout "$(yq -M -r .generics_version "/release/latest/base.yml")" )
fi

python3 /render-python-requirements.py
uv pip install --no-cache --system -r /requirements.extra.txt

mkdir -p /inventory.generics/
cp /generics/inventory/* /inventory.generics/

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

uv pip install --no-cache --system pyclean==3.0.0
pyclean /usr
uv pip uninstall --system pyclean
EOF

USER dragon

FROM python:3.13-alpine

COPY --link --from=builder / /

ENV PYTHONWARNINGS="ignore::UserWarning"

USER dragon

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/entrypoint.sh"]
VOLUME ["/extra", "/inventory", "/inventory.pre", "/opt/configuration"]
