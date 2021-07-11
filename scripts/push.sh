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

docker tag "$(git rev-parse --short HEAD)" "$REPOSITORY:$VERSION"
docker push "$REPOSITORY:$VERSION"
docker rmi "$REPOSITORY:$VERSION"
