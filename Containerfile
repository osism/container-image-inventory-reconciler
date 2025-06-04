# Multi-stage build for better layer caching and smaller final image
FROM python:3.13-alpine AS builder

# Build arguments
ARG VERSION=latest
ARG USER_ID=45000
ARG GROUP_ID=45000

# Environment variables
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
ENV TZ=UTC
# Fix netifaces compilation issue
ENV CFLAGS="-Wno-int-conversion"

# Install UV early for better caching
COPY --from=ghcr.io/astral-sh/uv:0.7.10 /uv /usr/local/bin/uv

# Install system dependencies in a single layer
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
  python3-dev \
  yq
EOF

# Copy requirement files first for better build caching
COPY --link files/requirements.txt /requirements.txt
COPY --link files/render-python-requirements.py /render-python-requirements.py
COPY --link files/templates /templates

# Install Python dependencies with build cache mount
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --no-cache --system -r /requirements.txt

# Clone repositories (can be cached if VERSION doesn't change)
RUN <<EOF
set -e
set -x

git clone https://github.com/osism/release /release
git clone https://github.com/osism/defaults /defaults
git clone https://github.com/osism/cfg-generics /generics

if [ "$VERSION" != "latest" ]; then
  ( cd /release || exit; git fetch --all --force; git checkout "inventory-reconciler-$VERSION" )
  ( cd /defaults || exit; git fetch --all --force; git checkout "$(yq -M -r .defaults_version "/release/latest/base.yml")" )
  ( cd /generics || exit; git fetch --all --force; git checkout "$(yq -M -r .generics_version "/release/latest/base.yml")" )
fi
EOF

# Install additional Python requirements
RUN <<EOF
set -e
python3 /render-python-requirements.py
cat /requirements.extra.txt
uv pip install --no-cache --system -r /requirements.extra.txt
EOF

# Copy application files after dependencies are installed
COPY --link files/ansible /ansible
COPY --link files/change.sh /change.sh
COPY --link files/entrypoint.sh /entrypoint.sh
COPY --link files/generate-clustershell-ansible-file.py /generate-clustershell-ansible-file.py
COPY --link files/handle-inventory-overwrite.py /handle-inventory-overwrite.py
COPY --link files/merge-ansible-cfg.py /merge-ansible-cfg.py
COPY --link files/merge-inventory-files.py /merge-inventory-files.py
COPY --link files/move-group-vars.py /move-group-vars.py
COPY --link files/netbox/ /netbox/
COPY --link files/prepare-vars.py /prepare-vars.py
COPY --link files/run.sh /run.sh

# Create user and prepare directories
RUN <<EOF
set -e
set -x

mkdir -p /inventory.generics/
cp /generics/inventory/* /inventory.generics/

addgroup -g $GROUP_ID dragon
adduser -D -u $USER_ID -G dragon dragon
adduser -D inventory-reconciler

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
EOF

# Clean up build dependencies and temporary files
RUN <<EOF
set -e
set -x

apk del .build-deps

rm -f \
  /render-python-requirements.py \
  /templates/requirements.txt.j2 \
  /requirements.extra.txt \
  /requirements.txt

# Clean Python cache
uv pip install --no-cache --system pyclean==3.0.0
pyclean /usr
uv pip uninstall --system pyclean

# Remove additional cache and temporary files
rm -rf /root/.cache
find /usr -type d -name '__pycache__' -exec rm -rf {} + || true
find /usr -type f -name '*.pyc' -delete || true
find /usr -type f -name '*.pyo' -delete || true
EOF

# Switch to non-root user
USER dragon

# Final stage - minimal runtime image
FROM python:3.13-alpine

# Copy everything from builder
COPY --link --from=builder / /

# Runtime environment
ENV PYTHONWARNINGS="ignore::UserWarning"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Security: Run as non-root user
USER dragon

# Set working directory
WORKDIR /inventory

# Define entrypoint and command
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/entrypoint.sh"]

# Define volumes
VOLUME ["/extra", "/inventory", "/inventory.pre", "/opt/configuration"]
