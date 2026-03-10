# TEE Attestor — Runs Reclaim attestor-core (zkTLS) + custom HTTP signing server
# inside Trusted Execution Environment (EigenCompute TDX)
#
# Services:
#   Port 8080 — Custom HTTP API (health, sign, verify, attestation, proxied /ws)
#   Port 8001 — Reclaim attestor-core WebSocket (zkTLS tunnel + claim signing)
#
# The proxy runs OUTSIDE the TEE (on the gateway host) and connects via WebSocket.

FROM node:22-slim AS attestor-core-build
WORKDIR /attestor-core
COPY attestor-core/ ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
RUN npm run build || true
RUN npm run download:zk-files 2>/dev/null || echo "ZK files download skipped"

FROM node:22-slim AS app-build
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src/ src/
RUN sed -i '/@reclaimprotocol\/attestor-core/d' package.json && \
    npm install --ignore-scripts && \
    npm run build

FROM node:22-slim
LABEL org.opencontainers.image.source=https://github.com/claw178-design/tee-attestor-real
WORKDIR /app

# Attestor-core (full source needed for --experimental-strip-types)
COPY --from=attestor-core-build /attestor-core/ /app/attestor-core/

# Our compiled app
COPY --from=app-build /app/dist/ dist/
COPY --from=app-build /app/package.json ./
RUN sed -i '/@reclaimprotocol\/attestor-core/d' package.json && \
    npm install --omit=dev --ignore-scripts

# Entrypoint that starts both services
COPY src/entrypoint-tee.ts ./entrypoint-tee.ts

ENV TEE_ATTESTOR_PORT=8080
ENV TEE_MEASUREMENT=eigencompute
ENV ATTESTOR_CORE_PORT=8001
ENV DISABLE_BGP_CHECKS=1

EXPOSE 8080

CMD ["node", "--experimental-strip-types", "entrypoint-tee.ts"]
