#!/usr/bin/env bash
set -euo pipefail

# Build the attestor-core TEE Docker image
# Uses the local attestor-core source from /tmp/attestor-core/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/.build"
IMAGE_NAME=${IMAGE_NAME:-ghcr.io/claw178-design/tee-attestor-real}
IMAGE_TAG=${IMAGE_TAG:-latest}

echo "[build] Preparing build context..."

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy attestor-core source
ATTESTOR_CORE_SRC=${ATTESTOR_CORE_SRC:-/tmp/attestor-core}
if [ ! -d "$ATTESTOR_CORE_SRC" ]; then
  echo "[build] ERROR: attestor-core not found at $ATTESTOR_CORE_SRC"
  echo "[build] Set ATTESTOR_CORE_SRC to the attestor-core directory"
  exit 1
fi

echo "[build] Copying attestor-core from $ATTESTOR_CORE_SRC ..."
rsync -a --exclude='node_modules' --exclude='.git' --exclude='lib' \
  "$ATTESTOR_CORE_SRC/" "$BUILD_DIR/attestor-core/"

# Copy Dockerfile, providers, and env
cp "$SCRIPT_DIR/Dockerfile" "$BUILD_DIR/"
cp -r "$SCRIPT_DIR/providers/" "$BUILD_DIR/providers/"
cp "$SCRIPT_DIR/.env.tee" "$BUILD_DIR/.env.tee"

echo "[build] Building Docker image: $IMAGE_NAME:$IMAGE_TAG"
docker build \
  --tag "$IMAGE_NAME:$IMAGE_TAG" \
  --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --label "org.opencontainers.image.revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
  "$BUILD_DIR"

echo "[build] Image built: $IMAGE_NAME:$IMAGE_TAG"
echo "[build] Size: $(docker image inspect "$IMAGE_NAME:$IMAGE_TAG" --format='{{.Size}}' | numfmt --to=iec 2>/dev/null || docker image inspect "$IMAGE_NAME:$IMAGE_TAG" --format='{{.Size}}')"

# Cleanup
rm -rf "$BUILD_DIR"

echo "[build] Done. Push with: docker push $IMAGE_NAME:$IMAGE_TAG"
