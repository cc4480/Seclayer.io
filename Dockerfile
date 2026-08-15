# --- Build stage: install all deps, build client + server, drop dev deps ---
FROM node:22-bookworm-slim AS build
WORKDIR /app

# better-sqlite3 installs via "prebuild-install || node-gyp rebuild". When the
# prebuilt binary cannot be downloaded (restricted networks, proxies, uncommon
# platforms) it compiles from source, which needs a toolchain. Installing it
# here keeps `npm ci` from failing the whole build; the runtime stage stays slim
# because it only copies the already-compiled node_modules.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

# --- Runtime stage: minimal image with prod deps + built artifacts ---
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/data/seclayer.sqlite

# Carry over pruned node_modules (incl. the prebuilt better-sqlite3 binary).
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# SQLite database lives on a persistent volume, owned by the unprivileged user
# the app runs as. Running a security scanner as root is unnecessary privilege.
RUN mkdir -p /data && chown -R node:node /data /app
USER node

VOLUME ["/data"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/api/system/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.cjs"]
