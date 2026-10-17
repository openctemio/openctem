# syntax=docker/dockerfile:1
# =============================================================================
# MULTI-STAGE DOCKERFILE
# =============================================================================

# -----------------------------------------------------------------------------
# Development stage - Standalone, no deps copy needed (uses volumes)
# -----------------------------------------------------------------------------
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS development

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
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS base

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
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS openapi
ARG SWAG_VERSION=v1.16.4
WORKDIR /app
ENV GOWORK=off
# swag type-checks the packages it parses, and with cgo on that compiles
# net's cgo resolver, which needs a C compiler this image does not have.
ENV CGO_ENABLED=0
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
#   server           the API, and the operator commands below: each is a link
#                    to the server binary, which runs the command named by the
#                    link (cmd/server/tools.go). One binary instead of one per
#                    command keeps the shared packages in the image once.
#     bootstrap-admin      initial setup: platform administrators and the
#                          first organization
#     refingerprint        re-keys findings to the current identity recipe (a
#                          dry run by default, RFC-043 §6)
#     repomerge            merges duplicate repository assets (a dry run by
#                          default)
#     ci-trust-scope-plan  dry run for adding existing CI trusts' repositories
#                          to scope (read-only)
#   openctem-signer  the job signer (RFC-040 §5.6); runs as its own container
#                    from this image, see deploy/docker-compose.job-signer.yml.
#                    A binary of its own: it holds the signing key and links
#                    none of the API.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -trimpath -ldflags="-s -w \
      -X github.com/openctemio/openctem/api/pkg/version.Version=${VERSION} \
      -X github.com/openctemio/openctem/api/pkg/version.Commit=${COMMIT} \
      -X github.com/openctemio/openctem/api/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /app/bin/ ./cmd/server ./cmd/signer \
 && mv /app/bin/signer /app/bin/openctem-signer


# -----------------------------------------------------------------------------
# Runtime filesystem additions: the users and the writable directories, made
# here because the production image has no shell to make them with.
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS runtime-base

FROM base AS runtime-fs
COPY --from=runtime-base /etc/passwd /etc/group /out/etc/
# openctem (1000) runs the API. The job signer runs as its own user (1001), in
# the API's group only so the API can reach its socket: its key and state are
# never the API's.
RUN echo 'openctem:x:1000:1000:openctem:/app:/sbin/nologin' >> /out/etc/passwd \
 && echo 'openctem-signer:x:1001:1000:openctem-signer:/var/lib/openctem-signer:/sbin/nologin' >> /out/etc/passwd \
 && echo 'openctem:x:1000:' >> /out/etc/group \
 && mkdir -p /out/app-data/attachments /out/signer-lib/keys /out/signer-lib/state /out/signer-run \
 && chmod 0700 /out/signer-lib/keys /out/signer-lib/state \
 && chmod 0770 /out/signer-run \
 && mkdir -p /out/tool-links \
 && for t in bootstrap-admin refingerprint repomerge ci-trust-scope-plan; do ln -s server /out/tool-links/$t; done

# -----------------------------------------------------------------------------
# Production stage
# -----------------------------------------------------------------------------
# Distroless static: CA certificates, time zones and the passwd entries above;
# no shell, no package manager, no busybox. The healthcheck is the server's
# own `-healthcheck`. To debug a running container use an ephemeral debug
# container (`docker debug`, `kubectl debug --target=<container>`).
FROM runtime-base AS production

WORKDIR /app

COPY --from=runtime-fs /out/etc/passwd /out/etc/group /etc/

# Everything below is owned by root and read-only to the runtime users: the API
# cannot rewrite its own binaries, spec, migrations or configs.
COPY --from=builder /app/bin/server /app/bin/openctem-signer ./
# The operator commands: /app/<command> -> server (see the builder stage).
COPY --from=runtime-fs /out/tool-links/ ./

# The OpenAPI spec served at /openapi.yaml (path relative to WORKDIR, see
# cmd/server/handlers.go NewDocsHandler).
COPY --from=openapi /app/api/openapi/swagger.yaml ./api/openapi/swagger.yaml

COPY --from=builder /app/migrations ./migrations
# The migrate wrapper of the migrations image, for the all-in-one image (a
# file here; this image never runs it).
COPY --from=builder /app/scripts/migrate-entrypoint.sh ./migrate-entrypoint.sh

# Copy sensor config templates (editable without rebuild — operators can
# mount a configmap/host volume on /app/configs to override)
COPY --from=builder /app/configs ./configs

# The only writable paths, with their owners, so a new named volume mounted on
# them starts with the right owner (Docker copies it into the volume).
#   /app/data                 the API: attachments (STORAGE_LOCAL_PATH default
#                             ./data/attachments) and the sensor CA
#                             (SENSOR_MTLS_CA_DIR default data/sensor-ca).
#                             Mount a volume there: the container filesystem is
#                             read-only in the Compose files and ephemeral anyway.
#   /var/lib/openctem-signer  the job signer's key and state (0700)
#   /run/openctem-signer      its socket, reachable by the API's group (0770)
COPY --from=runtime-fs --chown=1000:1000 /out/app-data /app/data
COPY --from=runtime-fs --chown=1001:1000 /out/signer-lib /var/lib/openctem-signer
COPY --from=runtime-fs --chown=1001:1000 /out/signer-run /run/openctem-signer

LABEL org.opencontainers.image.title="OpenCTEM API" \
      org.opencontainers.image.description="OpenCTEM API server, job signer and bootstrap-admin (distroless, non-root)" \
      org.opencontainers.image.source="https://github.com/openctemio/openctem" \
      org.opencontainers.image.licenses="GPL-3.0-only"

USER 1000:1000

EXPOSE 8080 8443

# `server -healthcheck` GETs /health on 127.0.0.1:$SERVER_PORT.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/server", "-healthcheck"]

ENTRYPOINT ["./server"]
