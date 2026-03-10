#!/usr/bin/env sh
set -e

echo "[entrypoint] Starting TEE Attestor Real"
echo "[entrypoint] TEE_TYPE=${TEE_TYPE:-unknown}"
echo "[entrypoint] TEE_ATTESTOR_PORT=${TEE_ATTESTOR_PORT:-8767}"

# Source compute environment if available (EigenCompute KMS)
if [ -f /usr/local/bin/compute-source-env.sh ]; then
  echo "[entrypoint] Sourcing compute environment..."
  . /usr/local/bin/compute-source-env.sh
fi

# Start the TEE attestor signing server
exec node /app/dist/tee-server.js
