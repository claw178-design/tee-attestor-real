# TEE Attestor Signing Server — runs inside Trusted Execution Environment
# Only the signing server (tee-server) runs here, NOT the proxy.
# The proxy runs on the gateway host and forwards claims to this container.

FROM node:22-slim AS build
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src/ src/
# Remove local-only attestor-core dep, install remaining deps, then build
RUN sed -i '/@reclaimprotocol\/attestor-core/d' package.json && \
    npm install --ignore-scripts && \
    npm run build

FROM node:22-slim
LABEL org.opencontainers.image.source=https://github.com/claw178-design/tee-attestor-real
WORKDIR /app
COPY --from=build /app/dist/ dist/
COPY --from=build /app/package.json ./
# Only need dotenv at runtime
RUN sed -i '/@reclaimprotocol\/attestor-core/d' package.json && \
    npm install --omit=dev --ignore-scripts

# TEE attestor listens on 8080 (EigenCompute standard)
ENV TEE_ATTESTOR_PORT=8080
ENV TEE_MEASUREMENT=eigencompute

EXPOSE 8080

CMD ["node", "dist/tee-server.js"]
