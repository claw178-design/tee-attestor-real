#!/usr/bin/env bash
set -euo pipefail

# EigenCompute deploy/upgrade for tee-attestor-real
#
# Usage:
#   ECLOUD_PRIVATE_KEY=... ./deploy.sh                  # deploy new
#   ECLOUD_PRIVATE_KEY=... APP_ID=0x... ./deploy.sh     # upgrade existing
#
# The script:
#   1. Builds a Docker image with a timestamped tag (not :latest)
#   2. Pushes to GHCR
#   3. Captures the image digest
#   4. Writes runtime .env with EIGEN_APP_ID + EIGEN_IMAGE_DIGEST
#   5. Deploys/upgrades on EigenCompute

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG_FILE="$SCRIPT_DIR/.env.local"
[ -f "$CFG_FILE" ] && source "$CFG_FILE"

ECLOUD_PRIVATE_KEY=${ECLOUD_PRIVATE_KEY:-0x038c5033e7a4be6af6ae4a23461f8204478c3a963f677f66b0108e7972193631}

APP_NAME=${APP_NAME:-tee-attestor-real}
APP_ID=${APP_ID:-0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5}
GHCR_REPO=${GHCR_REPO:-ghcr.io/claw178-design/tee-attestor-real}
LOG_VIS=${LOG_VIS:-public}
ENVIRON=${ECLOUD_ENV:-sepolia}
RUNTIME_ENV_FILE=${RUNTIME_ENV_FILE:-$SCRIPT_DIR/.env.eigencompute}
INSTANCE_TYPE=${INSTANCE_TYPE:-g1-standard-4t}
RESOURCE_USAGE=${RESOURCE_USAGE:-enable}
SKIP_BUILD=${SKIP_BUILD:-}

# ── Step 1: Build Docker image with timestamped tag ─────────────────
IMAGE_TAG="v2.0.0-$(date -u +%Y%m%d%H%M%S)"
IMAGE_REF="${GHCR_REPO}:${IMAGE_TAG}"

if [ -z "$SKIP_BUILD" ]; then
  echo "[build] Building Docker image: ${IMAGE_REF}"
  docker build --no-cache -t "$IMAGE_REF" -t "${GHCR_REPO}:latest" "$SCRIPT_DIR"

  echo "[push] Pushing ${IMAGE_REF} to GHCR..."
  docker push "$IMAGE_REF"
  docker push "${GHCR_REPO}:latest"

  # ── Step 2: Capture image digest ────────────────────────────────────
  IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_REF" 2>/dev/null | sed 's/.*@//' || true)
  if [ -z "$IMAGE_DIGEST" ]; then
    # Fallback: get from local image ID
    IMAGE_DIGEST="sha256:$(docker inspect --format='{{.Id}}' "$IMAGE_REF" | sed 's/sha256://')"
  fi
  echo "[digest] Image digest: ${IMAGE_DIGEST}"
else
  echo "[skip] Skipping build (SKIP_BUILD=1)"
  IMAGE_REF="${GHCR_REPO}:${IMAGE_TAG:-latest}"
  IMAGE_DIGEST="unknown"
fi

# ── Step 3: Write runtime env file with resolved values ─────────────
cat > "$RUNTIME_ENV_FILE" <<EOF
EIGEN_APP_ID=${APP_ID}
EIGEN_EVM_ADDRESS=${EIGEN_EVM_ADDRESS:-}
EIGEN_IMAGE_DIGEST=${IMAGE_DIGEST}
ECLOUD_ENV=${ENVIRON}
EIGEN_RUNTIME=1
TEE_ATTESTOR_PORT=3000
ATTESTOR_CORE_PORT=8001
TEE_MEASUREMENT=eigencompute
CLAIM_VERIFIER_ADDRESS=${CLAIM_VERIFIER_ADDRESS:-0xd957C897Bd5bA5D4969F3379D4f90da74Ab9763C}
DISABLE_BGP_CHECKS=1
DOMAIN=${DOMAIN:-zktls.judgeclaw.xyz}
APP_PORT=3000
ENABLE_CADDY_LOGS=true
ACME_STAGING=false
EOF
echo "[env] Wrote runtime env to ${RUNTIME_ENV_FILE}"

# ── Step 4: Deploy / Upgrade ─────────────────────────────────────────
ECLOUD_ARGS=(
  --image-ref "$IMAGE_REF"
  --log-visibility "$LOG_VIS"
  --environment "$ENVIRON"
  --instance-type "$INSTANCE_TYPE"
  --resource-usage-monitoring "$RESOURCE_USAGE"
  --private-key "$ECLOUD_PRIVATE_KEY"
  --env-file "$RUNTIME_ENV_FILE"
  --verbose
)

if [ -n "$APP_ID" ]; then
  echo "[upgrade] app=$APP_ID image=$IMAGE_REF env=$ENVIRON tag=$IMAGE_TAG"
  printf 'N\n' | ecloud compute app upgrade "$APP_ID" "${ECLOUD_ARGS[@]}"
else
  echo "[deploy] name=$APP_NAME image=$IMAGE_REF env=$ENVIRON tag=$IMAGE_TAG"
  ecloud compute app deploy --name "$APP_NAME" "${ECLOUD_ARGS[@]}"
fi

echo ""
echo "=== Deploy complete ==="
echo "Image:  ${IMAGE_REF}"
echo "Digest: ${IMAGE_DIGEST}"
echo "App ID: ${APP_ID}"
echo "Tag:    ${IMAGE_TAG}"
echo "Dashboard: https://verify-sepolia.eigencloud.xyz/app/${APP_ID}"
