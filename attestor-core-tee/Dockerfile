# TEE Attestor based on Reclaim Protocol attestor-core
# Runs inside EigenCompute TEE (TDX)
#
# Architecture:
#   Gateway client connects via WebSocket → attestor proxies TLS to upstream API
#   K2 KeyUpdate hides API key from attestor
#   ZK proofs verify response data integrity
#   Attestor signs claims with TEE-bound key

FROM node:22-slim

LABEL org.opencontainers.image.source=https://github.com/claw178-design/tee-attestor-real
LABEL org.opencontainers.image.description="zkTLS Attestor for AI API claims (Reclaim Protocol based)"

RUN apt-get update -y && apt-get install -y git python3 make g++ curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy attestor-core source (built from /tmp/attestor-core)
COPY attestor-core/ /app/

# Install all dependencies (need dev deps for type stripping)
RUN npm ci --ignore-scripts || npm install

# Download ZK circuit files (snarkjs artifacts for symmetric crypto proofs)
RUN npm run download:zk-files || echo "ZK files download skipped"

# Copy provider configs
COPY providers/ /app/providers/

# Copy TEE environment (keys embedded at build time)
# In production, these would come from TEE KMS or sealed storage
COPY .env.tee /app/.env.production

# Server config
ENV PORT=8001
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV DISABLE_BGP_CHECKS=1

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -sf http://localhost:8001/address || exit 1

EXPOSE 8001

# Run directly from TypeScript source using Node 22+ strip-types
CMD ["node", "--experimental-strip-types", "src/scripts/start-server.ts"]
