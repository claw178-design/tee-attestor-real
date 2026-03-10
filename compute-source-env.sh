#!/usr/bin/env sh
# Stub: source environment for EigenCompute runtime
# TODO: replace with real env sourcing (KMS secrets, attestation policy)
export EIGEN_RUNTIME=1
export WITNESS_MODE=mock
exec "$@"
