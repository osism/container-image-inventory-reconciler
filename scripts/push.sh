#!/usr/bin/env bash
set -x

# Available environment variables
#
# DOCKER_REGISTRY
# REPOSITORY
# VERSION

DOCKER_REGISTRY=${DOCKER_REGISTRY:-quay.io}

if [[ -n $DOCKER_REGISTRY ]]; then
    REPOSITORY="$DOCKER_REGISTRY/$REPOSITORY"
fi

buildah login --password $DOCKER_PASSWORD --username $DOCKER_USERNAME $DOCKER_REGISTRY

buildah tag "$(git rev-parse --short HEAD)" "$REPOSITORY:$VERSION"
buildah push "$REPOSITORY:$VERSION"
