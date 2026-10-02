# =============================================================================
# MULTI-STAGE DOCKERFILE
# =============================================================================

# -----------------------------------------------------------------------------
# Development stage - Standalone, no deps copy needed (uses volumes)
# -----------------------------------------------------------------------------
FROM golang:1.26.8-alpine AS development

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
EXPOSE 8080 9090 2345

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
FROM golang:1.26.8-alpine AS base

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set GOPRIVATE for private modules (SDK is private on GitHub)
ENV GOPRIVATE=github.com/openctemio/*

# Copy go mod files (context is api/ folder)
COPY go.mod go.sum ./

# Download dependencies (SDK fetched from GitHub)
RUN go mod download

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

# Build the main server
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -ldflags="-s -w \
      -X github.com/openctemio/openctem/api/pkg/version.Version=${VERSION} \
      -X github.com/openctemio/openctem/api/pkg/version.Commit=${COMMIT} \
      -X github.com/openctemio/openctem/api/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /app/bin/server ./cmd/server

# Build bootstrap-admin (initial setup: platform administrators and the first
# organization)
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -ldflags="-s -w" -o /app/bin/bootstrap-admin ./cmd/bootstrap-admin


# -----------------------------------------------------------------------------
# Production stage
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS production

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S openctem && \
    adduser -u 1000 -S openctem -G openctem

# Copy binaries from builder
COPY --from=builder /app/bin/server .
COPY --from=builder /app/bin/bootstrap-admin .

# Copy migrations if exist
COPY --from=builder /app/migrations ./migrations

# Copy sensor config templates (editable without rebuild — operators can
# mount a configmap/host volume on /app/configs to override)
COPY --from=builder /app/configs ./configs

# Change ownership
RUN chown -R openctem:openctem /app

# Switch to non-root user
USER openctem

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["./server"]
