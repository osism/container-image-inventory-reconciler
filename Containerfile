ARG PYTHON_VERSION=3.8
FROM python:${PYTHON_VERSION}-alpine

ARG USER_ID=45000
ARG GROUP_ID=45000

ENV TZ=UTC

ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/50-ceph /inventory.generics/50-ceph
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/50-infrastruture /inventory.generics/50-infrastruture
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/50-kolla /inventory.generics/50-kolla
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/50-monitoring /inventory.generics/50-monitoring
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/50-openstack /inventory.generics/50-openstack
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/51-ceph /inventory.generics/51-ceph
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/51-kolla /inventory.generics/51-kolla
ADD https://raw.githubusercontent.com/osism/cfg-generics/master/inventory/60-generic /inventory.generics/60-generic

COPY files/crontab /etc/crontabs/dragon
COPY files/entrypoint.sh /entrypoint.sh
COPY files/handle-inventory-overwrite.py /handle-inventory-overwrite.py
COPY files/requirements.txt /requirements.txt
COPY files/run.sh /run.sh

RUN apk add --no-cache \
      bash \
      git \
      rsync \
      tini \
      sudo \
    && apk add --no-cache --virtual .build-deps \
      build-base \
      libffi-dev \
    && pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir -r /requirements.txt \
    && adduser -D inventory-reconciler \
    && apk del .build-deps \
    && git clone --depth 1 https://github.com/osism/ansible-defaults /defaults \
    && addgroup -g $GROUP_ID dragon \
    && adduser -D -u $USER_ID -G dragon dragon \
    && mkdir -p /inventory /inventory.pre /opt/configuration/inventory \
    && chown -R dragon: /defaults /inventory /inventory.pre /inventory.generics /opt/configuration/inventory

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/entrypoint.sh"]

VOLUME /inventory
VOLUME /inventory.pre
VOLUME /opt/configuration/inventory

LABEL "org.opencontainers.image.documentation"="https://docs.osism.de" \
      "org.opencontainers.image.licenses"="ASL 2.0" \
      "org.opencontainers.image.source"="https://github.com/osism/container-image-inventory-reconciler" \
      "org.opencontainers.image.url"="https://www.osism.de" \
      "org.opencontainers.image.vendor"="Betacloud Solutions GmbH"
