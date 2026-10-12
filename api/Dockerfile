# syntax=docker/dockerfile:1
# =============================================================================
# MULTI-STAGE DOCKERFILE
# =============================================================================

# -----------------------------------------------------------------------------
# Development stage - Standalone, no deps copy needed (uses volumes)
# -----------------------------------------------------------------------------
FROM golang:1.26.9-alpine AS development

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata curl postgresql-client

# Install dev tools (pinned versions for reproducibility)
# hadolint ignore=DL3059
RUN go install github.com/air-verse/air@v1.64.0 && \
    go install github.com/go-delve/delve/cmd/dlv@v1.24.2 && \
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.18.3

# Copy entrypoint script
COPY scripts/dev-entrypoint.sh /usr/local/bin/dev-entrypoint.sh
RUN chmod +x /usr/local/bin/dev-entrypoint.sh

# Source and SDK mounted via volumes at runtime - no COPY needed

# Expose ports
EXPOSE 8080 8443 2345

# Run entrypoint (migrations + air)
# Development only, never published: it runs as root so the bind-mounted
# source tree, tmp/ and the go module/build cache volumes stay writable on any
# host uid. Published images are the `production` stage, which sets
# USER openctem.
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["/usr/local/bin/dev-entrypoint.sh"]

# -----------------------------------------------------------------------------
# Base stage for production builds
# SDK is fetched from GitHub as a released module (not local)
# Build context: api/ folder (not parent)
# -----------------------------------------------------------------------------
FROM golang:1.26.9-alpine AS base

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# openctemio modules are public: fetch them through the Go module proxy and
# verify them against the checksum database like every other dependency.

# Copy go mod files (context is api/ folder)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# -----------------------------------------------------------------------------
# OpenAPI spec stage
# -----------------------------------------------------------------------------
# The spec is generated from the handler annotations and is not committed
# (#1300), so the image generates it: GET /openapi.yaml and /docs serve
# /app/api/openapi/swagger.yaml. It is the same on every architecture, so it
# runs on the build platform (no emulation). Same swag version and flags as
# `make swagger` (SWAG_VERSION there and in scripts/check-openapi.sh).
FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine AS openapi
ARG SWAG_VERSION=v1.16.4
WORKDIR /app
ENV GOWORK=off
RUN go install github.com/swaggo/swag/cmd/swag@${SWAG_VERSION}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN swag init --generalInfo cmd/server/main.go --output api/openapi --outputTypes yaml --parseDependency --quiet \
 && test -s api/openapi/swagger.yaml

# -----------------------------------------------------------------------------
# Builder stage
# -----------------------------------------------------------------------------
FROM base AS builder
ARG TARGETOS
ARG TARGETARCH

# Copy API source code (context is api/ folder)
COPY . .

# Disable workspace mode for standalone build
ENV GOWORK=off

# Build identity, shown by GET /api/v1/version (Help > About). docker-publish.yml
# passes the tag, commit and build time; a build without them reports the
# checkout it runs in, or "dev".
ARG VERSION=""
ARG COMMIT=""
ARG BUILD_TIME=""

# Every binary in ONE go build: the packages they share compile once. The
# build cache is a BuildKit cache mount (local rebuilds recompile only what
# changed; it never ends up in a layer). -trimpath keeps the builder's paths
# out of the binaries, so the same source gives the same binary on any host.
# Binaries:
#   server           the API
#   bootstrap-admin  initial setup: platform administrators and the first
#                    organization
#   refingerprint    re-keys findings to the current identity recipe (a dry run
#                    by default, RFC-043 §6)
#   openctem-signer  the job signer (RFC-040 §5.6); runs as its own container
#                    from this image, see deploy/docker-compose.job-signer.yml
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -trimpath -ldflags="-s -w \
      -X github.com/openctemio/openctem/api/pkg/version.Version=${VERSION} \
      -X github.com/openctemio/openctem/api/pkg/version.Commit=${COMMIT} \
      -X github.com/openctemio/openctem/api/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /app/bin/ ./cmd/server ./cmd/bootstrap-admin ./cmd/refingerprint ./cmd/signer \
 && mv /app/bin/signer /app/bin/openctem-signer


# -----------------------------------------------------------------------------
# Production stage
# -----------------------------------------------------------------------------
# Alpine 3.20 reached end of support on 2026-04-01 (no more security fixes).
FROM alpine:3.22 AS production

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Non-root users. The job signer runs as its own user (uid 1001), in the API's
# group only so the API can reach its socket: its key and state are never the
# API's.
RUN addgroup -g 1000 -S openctem && \
    adduser -u 1000 -S openctem -G openctem && \
    adduser -u 1001 -S -G openctem openctem-signer

# Everything below is owned by root and read-only to the runtime users: the API
# cannot rewrite its own binaries, spec, migrations or configs. COPY sets the
# owner in the same layer (a later `chown -R` would store every file a second
# time in a new layer).
COPY --from=builder /app/bin/server /app/bin/bootstrap-admin /app/bin/refingerprint /app/bin/openctem-signer ./

# The OpenAPI spec served at /openapi.yaml (path relative to WORKDIR, see
# cmd/server/handlers.go NewDocsHandler).
COPY --from=openapi /app/api/openapi/swagger.yaml ./api/openapi/swagger.yaml

COPY --from=builder /app/migrations ./migrations
# The migrate wrapper of the migrations image, for the all-in-one image.
COPY --from=builder /app/scripts/migrate-entrypoint.sh ./migrate-entrypoint.sh

# Copy sensor config templates (editable without rebuild — operators can
# mount a configmap/host volume on /app/configs to override)
COPY --from=builder /app/configs ./configs

# The only writable paths, created here with their owners so a new named
# volume mounted on them starts with the right owner (Docker copies it into
# the volume); without it the volume root is root-owned and writes fail.
#   /app/data                 the API: attachments (STORAGE_LOCAL_PATH default
#                             ./data/attachments) and the sensor CA
#                             (SENSOR_MTLS_CA_DIR default data/sensor-ca).
#                             Mount a volume there: the container filesystem is
#                             read-only in the Compose files and ephemeral anyway.
#   /var/lib/openctem-signer  the job signer's key and state (0700)
#   /run/openctem-signer      its socket, reachable by the API's group (0770)
RUN mkdir -p /app/data/attachments \
      /var/lib/openctem-signer/keys /var/lib/openctem-signer/state /run/openctem-signer && \
    chown -R openctem:openctem /app/data && \
    chown -R openctem-signer:openctem /var/lib/openctem-signer /run/openctem-signer && \
    chmod 0700 /var/lib/openctem-signer/keys /var/lib/openctem-signer/state && \
    chmod 0770 /run/openctem-signer

# Switch to non-root user
USER openctem

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["./server"]
