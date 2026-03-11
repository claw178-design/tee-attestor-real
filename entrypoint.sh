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

# Detect TLS mode:
# On EigenCompute, compute-source-env.sh runs BEFORE this entrypoint and:
#   1. Obtains TLS certs via tls-keygen → /run/tls/
#   2. Starts Caddy on :8080 (HTTPS) proxying to APP_PORT
# So we just need to set Node.js to listen on APP_PORT (not 8080).
TLS_CERT="/run/tls/fullchain.pem"
TLS_KEY="/run/tls/privkey.pem"
CADDY_RUNNING=$(pgrep -x caddy > /dev/null 2>&1 && echo "yes" || echo "no")

if [ "$CADDY_RUNNING" = "yes" ]; then
  # EigenCompute's compute-source-env.sh already started Caddy
  echo "[entrypoint] Caddy already running (started by EigenCompute)"
  export TEE_ATTESTOR_PORT="${APP_PORT:-3000}"
  echo "[entrypoint] Caddy :8080 (HTTPS) → Node.js :${TEE_ATTESTOR_PORT}"
elif [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; then
  # Certs exist but Caddy not running — start it ourselves
  echo "[entrypoint] TLS certs found, starting Caddy for HTTPS on :8080"
  export TEE_ATTESTOR_PORT="${APP_PORT:-3000}"
  echo "[entrypoint] Caddy :8080 (HTTPS) → Node.js :${TEE_ATTESTOR_PORT}"
  caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
else
  echo "[entrypoint] No TLS available — Node.js serves HTTP on :8080 directly"
  export TEE_ATTESTOR_PORT=8080
fi

echo "[entrypoint] EIGEN_APP_ID=${EIGEN_APP_ID:-<not set>}"
echo "[entrypoint] EIGEN_IMAGE_DIGEST=${EIGEN_IMAGE_DIGEST:-<not set>}"
echo "[entrypoint] EIGEN_EVM_ADDRESS=${EIGEN_EVM_ADDRESS:-<not set>}"
echo "[entrypoint] DOMAIN=${DOMAIN:-<not set>}"

# Start Node.js app (foreground)
exec node dist/entrypoint-tee.js
