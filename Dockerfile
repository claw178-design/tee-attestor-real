# TEE Attestor — Reclaim attestor-core (zkTLS) + custom HTTP signing server
# Single port (8080): HTTP API + WebSocket proxy to internal attestor-core
#
# Architecture:
#   Gateway Client ──WebSocket /ws──→ [8080] ──proxy──→ [8001] attestor-core
#                                     [8080] HTTP API (health, sign, verify, attestation)
#
# No separate proxy needed — attestor-core IS the TLS tunnel.

FROM node:22-slim AS attestor-core-build
RUN apt-get update -y && apt-get install -y python3 make g++ git && rm -rf /var/lib/apt/lists/*
WORKDIR /attestor-core
COPY attestor-core/ ./
# Install all deps (including native: re2, koffi)
RUN npm ci 2>/dev/null || npm install
# Build TypeScript
RUN npm run build || true
# Download ZK verification circuits
RUN npm run download:zk-files 2>/dev/null || echo "ZK files skipped"

FROM node:22-slim AS app-build
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src/ src/
# Install all deps (dev included for TS build), strip attestor-core (local tgz path)
RUN sed -i '/@reclaimprotocol\/attestor-core/d' package.json && \
    npm install --ignore-scripts && \
    npx tsc

FROM node:22-slim
RUN apt-get update -y && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source=https://github.com/claw178-design/tee-attestor-real
LABEL org.opencontainers.image.description="zkTLS Attestor (Reclaim Protocol) in TEE — All-Hash, K2 API key hiding"
WORKDIR /app

# Attestor-core with full source + node_modules (for --experimental-strip-types runtime)
COPY --from=attestor-core-build /attestor-core/ /app/attestor-core/

# Our compiled HTTP server + entrypoint
COPY --from=app-build /app/dist/ dist/
COPY --from=app-build /app/package.json ./
# Only production deps (ethers)
RUN npm install --omit=dev --ignore-scripts

ENV TEE_ATTESTOR_PORT=8080
ENV ATTESTOR_CORE_PORT=8001
ENV TEE_MEASUREMENT=eigencompute
ENV DISABLE_BGP_CHECKS=1
ENV NODE_ENV=production

EXPOSE 8080

CMD ["node", "dist/entrypoint-tee.js"]
