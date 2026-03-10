#!/bin/bash
set -e

echo "============================================================"
echo "[entrypoint] TEE Attestor — zkTLS + HTTP Signing Server"
echo "[entrypoint] Date: $(date -u)"
echo "============================================================"

# Source KMS env if available (EigenCompute injects via compute-source-env.sh)
if [ -f /tmp/.env ]; then
  echo "[entrypoint] Loading /tmp/.env (non-empty values only)"
  while IFS='=' read -r key val; do
    key=$(echo "$key" | xargs)
    [[ -z "$key" || "$key" == \#* ]] && continue
    val=$(echo "$val" | xargs | sed "s/^['\"]//;s/['\"]$//")
    [ -n "$val" ] && export "$key=$val"
  done < /tmp/.env
fi

# Also source our baked-in env file (fills in anything still missing)
if [ -f /app/.env.eigencompute ]; then
  echo "[entrypoint] Loading /app/.env.eigencompute (fill missing)"
  while IFS='=' read -r key val; do
    key=$(echo "$key" | xargs)
    [[ -z "$key" || "$key" == \#* ]] && continue
    val=$(echo "$val" | xargs | sed "s/^['\"]//;s/['\"]$//")
    eval "current=\${$key:-}"
    [ -z "$current" ] && [ -n "$val" ] && export "$key=$val"
  done < /app/.env.eigencompute
fi

# Auto-detect EIGEN_APP_ID from hostname if not set
if [ -z "${EIGEN_APP_ID:-}" ]; then
  HOSTNAME_VAL=$(hostname)
  if [[ "$HOSTNAME_VAL" =~ tee-(0x[0-9a-fA-F]+) ]]; then
    export EIGEN_APP_ID="${BASH_REMATCH[1]}"
    echo "[entrypoint] Auto-detected EIGEN_APP_ID from hostname: $EIGEN_APP_ID"
  fi
fi

# If EigenCompute's TLS layer is active (Caddy on 8080), our app moves to APP_PORT
# Detect by checking if compute-source-env.sh set up TLS
if [ -f /usr/local/bin/tls-keygen ]; then
  echo "[entrypoint] TLS available (tls-keygen found)"
  echo "[entrypoint] EigenCompute Caddy handles port 8080 (HTTPS)"
  export TEE_ATTESTOR_PORT="${APP_PORT:-8081}"
  echo "[entrypoint] Node.js on port: ${TEE_ATTESTOR_PORT}"
else
  echo "[entrypoint] No TLS layer detected — Node.js serves 8080 directly"
  export TEE_ATTESTOR_PORT=8080
fi

echo "[entrypoint] EIGEN_APP_ID=${EIGEN_APP_ID:-<not set>}"
echo "[entrypoint] EIGEN_IMAGE_DIGEST=${EIGEN_IMAGE_DIGEST:-<not set>}"
echo "[entrypoint] EIGEN_EVM_ADDRESS=${EIGEN_EVM_ADDRESS:-<not set>}"
echo "[entrypoint] DOMAIN=${DOMAIN:-<not set>}"

# Start Node.js app (foreground)
exec node dist/entrypoint-tee.js
