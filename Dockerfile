FROM node:20-slim AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npx tsc

# Production stage
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --production

COPY --from=builder /app/dist/ ./dist/

# Copy .env.example as reference
COPY .env.example ./

EXPOSE 8080

# Default: run CLI help. Override with docker run args.
# Examples:
#   docker run -e OPENAI_API_KEY=sk-... attestor attest --provider openai --prompt "Hello"
#   docker run attestor verify --claim /data/claim.json --field model --value gpt-4
CMD ["node", "dist/cli.js", "--help"]
