#!/usr/bin/env bash
set -x

# Available environment variables
#
# BUILD_OPTS
# PYTHON_VERSION
# VERSION

# Set default values

BUILD_OPTS=${BUILD_OPTS:-}
CREATED=$(date --rfc-3339=ns)
PYTHON_VERSION=${PYTHON_VERSION:-3.8}
REVISION=$(git rev-parse HEAD)
VERSION=${VERSION:-latest}

buildah build-using-dockerfile \
    --format docker \
    --build-arg "PYTHON_VERSION=$PYTHON_VERSION" \
    --build-arg "VERSION=$VERSION" \
    --tag "$(git rev-parse --short HEAD)" \
    --label "org.opencontainers.image.created=$CREATED" \
    --label "org.opencontainers.image.documentation=https://docs.osism.tech" \
    --label "org.opencontainers.image.licenses=ASL 2.0" \
    --label "org.opencontainers.image.revision=$REVISION" \
    --label "org.opencontainers.image.source=https://github.com/osism/container-image-inventory-reconciler" \
    --label "org.opencontainers.image.title=osism-ansible" \
    --label "org.opencontainers.image.url=https://www.osism.tech" \
    --label "org.opencontainers.image.vendor=OSISM GmbH" \
    --label "org.opencontainers.image.version=$VERSION" \
    $BUILD_OPTS .
