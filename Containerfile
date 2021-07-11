ARG PYTHON_VERSION=3.8
FROM python:${PYTHON_VERSION}-alpine

ARG VERSION

ARG USER_ID=45000
ARG GROUP_ID=45000

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV TZ=UTC

COPY files/crontab /etc/crontabs/dragon
COPY files/entrypoint.sh /entrypoint.sh
COPY files/handle-inventory-overwrite.py /handle-inventory-overwrite.py
COPY files/requirements.txt /requirements.txt
COPY files/run.sh /run.sh
COPY files/playbooks /playbooks

RUN apk add --no-cache \
      bash \
      git \
      jq \
      rsync \
      sudo \
      tini \
    && apk add --no-cache --virtual .build-deps \
      build-base \
      libffi-dev \
      openssl-dev \
      python3-dev \
    && pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir -r /requirements.txt \
    && git clone https://github.com/osism/release /release \
    && git clone https://github.com/osism/ansible-defaults /defaults \
    && ( cd /defaults || exit; git fetch --all --force; git checkout "$(yq -M -r .defaults_version "/release/$VERSION/base.yml")" ) \
    && git clone https://github.com/osism/cfg-generics /generics \
    && ( cd /generics || exit; git fetch --all --force; git checkout "$(yq -M -r .generics_version "/release/$VERSION/base.yml")" ) \
    && mkdir -p /inventory.generics/ \
    && cp /generics/inventory/50-ceph /inventory.generics/50-ceph \
    && cp /generics/inventory/50-infrastruture /inventory.generics/50-infrastruture \
    && cp /generics/inventory/50-kolla /inventory.generics/50-kolla \
    && cp /generics/inventory/50-monitoring /inventory.generics/50-monitoring \
    && cp /generics/inventory/50-openstack /inventory.generics/50-openstack \
    && cp /generics/inventory/51-ceph /inventory.generics/51-ceph \
    && cp /generics/inventory/51-kolla /inventory.generics/51-kolla \
    && cp /generics/inventory/60-generic /inventory.generics/60-generic \
    && adduser -D inventory-reconciler \
    && apk del .build-deps \
    && addgroup -g $GROUP_ID dragon \
    && adduser -D -u $USER_ID -G dragon dragon \
    && mkdir -p \
      /inventory \
      /inventory.pre \
      /opt/configuration/inventory \
      /extra \
    && chown -R dragon: \
      /defaults \
      /inventory \
      /inventory.pre \
      /inventory.generics \
      /opt/configuration/inventory \
      /extra \
    && rm /etc/crontabs/root

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/entrypoint.sh"]

VOLUME /extra
VOLUME /inventory
VOLUME /inventory.pre
VOLUME /opt/configuration/inventory
