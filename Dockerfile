# TEE Attestor — Reclaim attestor-core (zkTLS) + custom HTTP signing server
#
# Architecture:
#   Internet ──8080──→ [Node.js entrypoint-tee.js]
#     HTTP API: /health, /sign, /verify, /attestation, /pubkey, /eth-sign
#     WS proxy: /ws → internal attestor-core (port 8001)
#   EigenCompute optionally adds TLS via Caddy on port 8080 → APP_PORT

FROM node:22-slim AS attestor-core-build
RUN apt-get update -y && apt-get install -y python3 make g++ git && rm -rf /var/lib/apt/lists/*
WORKDIR /attestor-core
COPY attestor-core/ ./
RUN npm ci 2>/dev/null || npm install
RUN npm run build || true
RUN npm run download:zk-files 2>/dev/null || echo "ZK files skipped"

FROM node:22-slim AS app-build
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src/ src/
RUN sed -i '/@reclaimprotocol\/attestor-core/d' package.json && \
    npm install --ignore-scripts && \
    npx tsc

FROM node:22-slim
RUN apt-get update -y && apt-get install -y python3 make g++ curl caddy && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source=https://github.com/claw178-design/tee-attestor-real
LABEL org.opencontainers.image.description="zkTLS Attestor (Reclaim Protocol) in TEE — All-Hash, K2 API key hiding"
WORKDIR /app

# Attestor-core with full source + node_modules
COPY --from=attestor-core-build /attestor-core/ /app/attestor-core/

# Our compiled HTTP server + entrypoint
COPY --from=app-build /app/dist/ dist/
COPY --from=app-build /app/package.json ./
RUN npm install --omit=dev --ignore-scripts

# Caddyfile for EigenCompute TLS (used when tls-keygen is available)
COPY Caddyfile /etc/caddy/Caddyfile

# Shell entrypoint
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Runtime env file (fallback values baked into image)
COPY .env.eigencompute /app/.env.eigencompute

# Default: Node.js on 8080 directly.
# When EigenCompute TLS is active, Caddy takes 8080 and we use APP_PORT.
ENV TEE_ATTESTOR_PORT=8080
ENV ATTESTOR_CORE_PORT=8001
ENV TEE_MEASUREMENT=eigencompute
ENV DISABLE_BGP_CHECKS=1
ENV NODE_ENV=production
ENV DOMAIN=zktls.judgeclaw.xyz
ENV APP_PORT=8080

EXPOSE 8080

CMD ["/app/entrypoint.sh"]
