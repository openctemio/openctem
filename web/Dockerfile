# syntax=docker/dockerfile:1
# ==============================================================================
# Multi-Stage Dockerfile for Next.js 16
# ==============================================================================
# Single Dockerfile with targets for both development and production.
#
# Development (with hot reload):
#   docker-compose up
#   OR: docker build --target development -t ui:dev .
#
# Production:
#   api/deploy/docker-compose.yml (the whole stack behind one HTTPS port)
#   OR: docker build --target production -t ui:prod .
# ==============================================================================

# ==============================================================================
# BASE STAGE - Common dependencies
# ==============================================================================
FROM node:26-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS base

# Add libc6-compat for Alpine compatibility with some npm packages
RUN apk add --no-cache libc6-compat

WORKDIR /app

# ==============================================================================
# DEPS STAGE - Install dependencies
# ==============================================================================
FROM base AS deps

# Copy package files
COPY package.json package-lock.json* ./

# Install all dependencies with BuildKit cache mount for faster builds
# Cache is shared across builds, significantly speeding up npm ci
RUN --mount=type=cache,target=/root/.npm \
    npm ci

# ==============================================================================
# DEVELOPMENT STAGE - Hot reload enabled
# ==============================================================================
FROM base AS development

WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy package.json for scripts
COPY package.json ./

# Set development environment
ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1

# Enable file watching in Docker (required for hot reload)
ENV WATCHPACK_POLLING=true
ENV CHOKIDAR_USEPOLLING=true

# Expose port
EXPOSE 3000

# Start development server with Turbopack
CMD ["npm", "run", "dev"]

# ==============================================================================
# BUILDER STAGE - Build production application
# ==============================================================================
FROM base AS builder

WORKDIR /app

# Copy dependencies
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Build-time environment variables (NEXT_PUBLIC_*)
# These are baked into the client bundle - NEVER put secrets here!
ARG NEXT_PUBLIC_APP_URL
ARG NEXT_PUBLIC_SENTRY_DSN
# Release version and commit, shown in Help > About (empty outside releases)
ARG NEXT_PUBLIC_APP_VERSION
ARG NEXT_PUBLIC_APP_COMMIT
# Server-side only (NOT exposed to browser)
ARG BACKEND_API_URL

# Set environment for build
ENV DOCKER_BUILD=true
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Pass build args to env (NEXT_PUBLIC_* are baked into client bundle)
ENV NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL
ENV NEXT_PUBLIC_SENTRY_DSN=$NEXT_PUBLIC_SENTRY_DSN
ENV NEXT_PUBLIC_APP_VERSION=$NEXT_PUBLIC_APP_VERSION
ENV NEXT_PUBLIC_APP_COMMIT=$NEXT_PUBLIC_APP_COMMIT
# Server-side only
ENV BACKEND_API_URL=$BACKEND_API_URL

# Build application
RUN npm run build

# ==============================================================================
# CONSOLE: the platform administration console (web/console), its own image
# ==============================================================================
# Its own Next.js app built from the same dependencies (RFC-022 revision 21):
#   docker build --target console -t openctem-console .
# The tenant image (production, the last and default stage) contains no console route and this one no tenant
# route. Same minimal runtime: Alpine + node, no package manager, non-root,
# read-only application files.
FROM base AS console-builder

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_APP_VERSION
ARG NEXT_PUBLIC_APP_COMMIT
ENV DOCKER_BUILD=true
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_PUBLIC_APP_VERSION=$NEXT_PUBLIC_APP_VERSION
ENV NEXT_PUBLIC_APP_COMMIT=$NEXT_PUBLIC_APP_COMMIT

RUN npm run build:console

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS console

RUN apk add --no-cache libstdc++ libgcc libatomic
COPY --from=base /usr/local/bin/node /usr/local/bin/node
RUN node --version

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

RUN addgroup -S -g 1001 nodejs && \
  adduser -S -D -H -u 1001 -G nodejs -h /app nextjs

# The standalone build of web/console keeps its path under the tracing root
# (web/): the server is console/server.js. Writable only: console/.next/cache
# (and /tmp), as for the tenant image.
COPY --from=console-builder /app/console/.next/standalone ./
COPY --from=console-builder /app/console/.next/static ./console/.next/static
RUN mkdir -p console/.next/cache && chown nextjs:nodejs console/.next/cache

LABEL org.opencontainers.image.title="OpenCTEM platform console" \
      org.opencontainers.image.description="OpenCTEM platform administration console (Next.js standalone, non-root)" \
      org.opencontainers.image.source="https://github.com/openctemio/openctem" \
      org.opencontainers.image.licenses="GPL-3.0-only"

USER nextjs
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "console/server.js"]

# ==============================================================================
# PRODUCTION STAGE - Minimal production image
# ==============================================================================
# Plain Alpine plus the node binary of the base stage, and nothing else: no
# npm/npx (a runtime image must not carry a package manager, and npm's bundled
# dependency tree carried advisories none of this image's code can reach), no
# C headers, no glibc shim. Deleting npm in a later layer would still ship its
# bytes in the base layer; not copying it ships none. Keep this Alpine release
# the one the node image is built on (node:26-alpine), so node finds the C++
# runtime it was linked against; `node --version` below fails the build
# otherwise.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS production

# node's shared libraries (see `ldd /usr/local/bin/node` in the node image).
RUN apk add --no-cache libstdc++ libgcc libatomic && apk upgrade --no-cache zlib
COPY --from=base /usr/local/bin/node /usr/local/bin/node
RUN node --version

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Non-root runtime user (same uid/gid as before: 1001 nextjs / 1001 nodejs).
RUN addgroup -S -g 1001 nodejs && \
  adduser -S -D -H -u 1001 -G nodejs -h /app nextjs

# The application is owned by root and read-only to the runtime user, which
# cannot rewrite its own server code. The standalone server writes only under
# .next/cache (image and fetch caches) and /tmp, so .next/cache is the one
# directory it owns, and the image runs with a read-only root filesystem when
# those two are writable mounts:
#   read_only: true
#   tmpfs: [/tmp, "/app/.next/cache:uid=1001,gid=1001"]
# (api/deploy/docker-compose.yml does this).
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
# Production entry: the standalone server plus same-origin WebSocket forwarding
# of /api/v1/ws to BACKEND_API_URL (read at start, not frozen into the build).
COPY --from=builder /app/server-with-ws.mjs ./server-with-ws.mjs
RUN mkdir -p .next/cache && chown nextjs:nodejs .next/cache

LABEL org.opencontainers.image.title="OpenCTEM web console" \
      org.opencontainers.image.description="OpenCTEM web console (Next.js standalone, non-root)" \
      org.opencontainers.image.source="https://github.com/openctemio/openctem" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/health || exit 1

# Start application
CMD ["node", "server-with-ws.mjs"]

