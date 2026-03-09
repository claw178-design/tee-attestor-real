FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --production

COPY dist/ ./dist/

EXPOSE 8080

CMD ["node", "dist/index.js"]
