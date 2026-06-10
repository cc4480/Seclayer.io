# syntax=docker/dockerfile:1

# --- Stage 1: build the client bundle and server bundle ---
FROM node:22-alpine AS builder
WORKDIR /app

# Install dependencies against the lockfile for reproducible builds.
COPY package.json package-lock.json ./
RUN npm ci

# Build the Vite client and the bundled CJS server.
COPY . .
RUN npm run build

# --- Stage 2: install production-only dependencies ---
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# --- Stage 3: minimal runtime image ---
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    LOG_JSON=true

# Run as the unprivileged "node" user shipped with the base image.
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist
COPY --chown=node:node package.json ./

USER node
EXPOSE 3000

# Container-level liveness check hitting the health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/system/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.cjs"]
