# =============================================================================
# MULTI-STAGE DOCKERFILE
# =============================================================================

# -----------------------------------------------------------------------------
# Development stage - Standalone, no deps copy needed (uses volumes)
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/golang:1.25-alpine AS development

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
CMD ["/usr/local/bin/dev-entrypoint.sh"]

# -----------------------------------------------------------------------------
# Base stage for production builds
# SDK is fetched from GitHub as a released module (not local)
# Build context: api/ folder (not parent)
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/golang:1.25-alpine AS base

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

# Build the main server
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -ldflags="-s -w" -o /app/bin/server ./cmd/server

# Build bootstrap-admin (for initial setup)
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -ldflags="-s -w" -o /app/bin/bootstrap-admin ./cmd/bootstrap-admin

# -----------------------------------------------------------------------------
# Production stage
# -----------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/alpine:3.20 AS production

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
