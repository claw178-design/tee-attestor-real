#!/usr/bin/env bash
set -euo pipefail

# EigenCompute deploy/upgrade for tee-attestor-real
#
# Usage:
#   ECLOUD_PRIVATE_KEY=... ./deploy.sh                  # deploy new
#   ECLOUD_PRIVATE_KEY=... APP_ID=0x... ./deploy.sh     # upgrade existing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG_FILE="$SCRIPT_DIR/.env.local"
[ -f "$CFG_FILE" ] && source "$CFG_FILE"

ECLOUD_PRIVATE_KEY=${ECLOUD_PRIVATE_KEY:-0x038c5033e7a4be6af6ae4a23461f8204478c3a963f677f66b0108e7972193631}

APP_NAME=${APP_NAME:-tee-attestor-real}
APP_ID=${APP_ID:-}
IMAGE_REF=${IMAGE_REF:-ghcr.io/claw178-design/tee-attestor-real:latest}
LOG_VIS=${LOG_VIS:-public}
ENVIRON=${ECLOUD_ENV:-sepolia}
RUNTIME_ENV_FILE=${RUNTIME_ENV_FILE:-}
INSTANCE_TYPE=${INSTANCE_TYPE:-g1-standard-4t}
RESOURCE_USAGE=${RESOURCE_USAGE:-enable}

ECLOUD_ARGS=(
  --image-ref "$IMAGE_REF"
  --log-visibility "$LOG_VIS"
  --environment "$ENVIRON"
  --instance-type "$INSTANCE_TYPE"
  --resource-usage-monitoring "$RESOURCE_USAGE"
  --private-key "$ECLOUD_PRIVATE_KEY"
  --verbose
)

if [ -n "$RUNTIME_ENV_FILE" ] && [ -f "$RUNTIME_ENV_FILE" ]; then
  ECLOUD_ARGS+=( --env-file "$RUNTIME_ENV_FILE" )
else
  export ECLOUD_ENVFILE_PATH=/dev/null
fi

if [ -n "$APP_ID" ]; then
  echo "[upgrade] app=$APP_ID image=$IMAGE_REF env=$ENVIRON"
  printf 'N\n' | ecloud compute app upgrade "$APP_ID" ${ECLOUD_ARGS[@]}
else
  echo "[deploy] name=$APP_NAME image=$IMAGE_REF env=$ENVIRON"
  ecloud compute app deploy --name "$APP_NAME" ${ECLOUD_ARGS[@]}
fi
