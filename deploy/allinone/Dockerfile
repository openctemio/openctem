# syntax=docker/dockerfile:1.7
#
# ghcr.io/openctemio/openctem — the all-in-one image: API + web console + the
# OpenCTEM gateway (Caddy) in ONE container; Postgres and Redis are external.
#
#   GATEWAY=on  (default)  only the gateway listens on a routable address: one
#                          HTTPS port, :443 (api and web bind to 127.0.0.1)
#   GATEWAY=off            :8080 (API) and :3000 (web) are served directly, no Caddy
#
# The gateway is NOT a copy: it is api/deploy/gateway (Caddyfile, TLS modes,
# entrypoint) — the same files the split Compose deployment
# (api/deploy/docker-compose.yml) runs, passed in as a named build context.
# Routing, TLS modes (internal | acme | files | http) and their refusals are
# therefore identical in both deployments, and Gateway Routing in API CI tests
# them for both.
#
# It is ASSEMBLED from the two per-component images of the same release instead
# of rebuilding them, so the bytes inside are exactly what openctem-api and
# openctem-web ship (one build, one SBOM per component, no drift):
#
#   docker buildx build deploy/allinone \
#     --build-context gateway=api/deploy/gateway \
#     --build-arg API_IMAGE=ghcr.io/openctemio/openctem-api:vX.Y.Z \
#     --build-arg WEB_IMAGE=ghcr.io/openctemio/openctem-web:vX.Y.Z
#
# With a multi-arch API_IMAGE/WEB_IMAGE, BuildKit picks the variant matching
# the platform being built. TARGETARCH/TARGETOS are deliberately never given a
# default anywhere in this file: `ARG TARGETARCH=amd64` overrides BuildKit's
# automatic value and ships amd64 binaries in the arm64 image (that happened to
# the sensor images). Nothing here needs them: every binary is either copied
# from a per-arch image or compiled natively for the build platform's target.

ARG API_IMAGE
ARG WEB_IMAGE
# The platform console (web/console, its own image: RFC-022 revision 21).
ARG CONSOLE_IMAGE
# Go and Alpine are pinned by digest in the FROM lines below, where Dependabot
# finds and refreshes them (it does not read ARG defaults). The runtime Alpine
# must stay the release the web image's node binary is built on
# (node:26-alpine): node needs the C++ runtime it was linked against, and
# `node --version` below fails the build otherwise.

FROM ${API_IMAGE} AS api
FROM ${WEB_IMAGE} AS web
FROM ${CONSOLE_IMAGE} AS console

# golang-migrate, same version as CI (api-ci.yml). Built in the target
# platform's own stage, so no arch-specific download URL to get wrong.
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS migrate
RUN CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" -tags postgres \
      github.com/golang-migrate/migrate/v4/cmd/migrate@v4.18.1 \
 && cp "$(go env GOPATH)/bin/migrate" /usr/local/bin/migrate

# Caddy, the same release as the gateway image (api/deploy/gateway/Dockerfile
# CADDY_VERSION) with the standard modules, compiled here with the pinned Go
# above rather than copied from the caddy image: the published binary carries
# the Go standard library it was released with, and every standard-library
# advisory since then with it. CADDY_DEPS raises dependencies that have
# security fixes newer than the Caddy release; drop an entry once a Caddy
# release requires that version itself.
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS caddy
ARG CADDY_VERSION=v2.11.4
ARG CADDY_DEPS="golang.org/x/net@v0.60.0 google.golang.org/grpc@v1.83.2"
WORKDIR /src
RUN printf '%s\n' 'package main' \
      'import (' \
      '	caddycmd "github.com/caddyserver/caddy/v2/cmd"' \
      '	_ "github.com/caddyserver/caddy/v2/modules/standard"' \
      ')' \
      'func main() { caddycmd.Main() }' > main.go \
 && go mod init openctem.local/caddy \
 && go get "github.com/caddyserver/caddy/v2@${CADDY_VERSION}" ${CADDY_DEPS} \
 && go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/bin/caddy . \
 && /usr/bin/caddy version | grep -q "^${CADDY_VERSION} " \
 && apk add --no-cache libcap-setcap \
 && setcap cap_net_bind_service=+ep /usr/bin/caddy

# Final image: plain Alpine with the tools the scripts below need (bash and
# psql for the supervisor's migration lock, wget for the healthcheck, tini as
# PID 1) and node from the web image. The API, migrate and Caddy are static
# binaries. Every file is copied in with its final owner: no `cp -a` or
# `chown -R` afterwards, which stored the whole web and API a second (and
# third) time in new layers.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS final
RUN apk add --no-cache tini bash ca-certificates tzdata wget postgresql17-client \
      libstdc++ libgcc libatomic \
 && addgroup -S -g 1001 nodejs \
 && adduser -S -D -H -u 1001 -G nodejs -h /opt/openctem nextjs
COPY --from=web /usr/local/bin/node /usr/local/bin/node
RUN node --version

# Owned by root and read-only to the runtime user (uid 1001): the processes
# cannot rewrite their own code.
# web: the standalone Next.js server as built by web/Dockerfile (WORKDIR /app there)
COPY --from=web --chown=0:0 /app /opt/openctem/web
# console: the platform console's standalone server (console/server.js)
COPY --from=console --chown=0:0 /app /opt/openctem/console
# api: server + admin tool + migrations + configs (WORKDIR /app in api/Dockerfile)
# (the API image's operator commands are links to the server binary, see
# api/Dockerfile; this image keeps bootstrap-admin, linked below)
COPY --from=api --chown=0:0 /app/server /opt/openctem/api/
COPY --from=api --chown=0:0 /app/migrations /opt/openctem/api/migrations
COPY --from=api --chown=0:0 /app/configs /opt/openctem/api/configs
# The OpenAPI spec the API serves at /openapi.yaml (relative to its working dir).
COPY --from=api --chown=0:0 /app/api/openapi/swagger.yaml /opt/openctem/api/api/openapi/swagger.yaml
COPY --from=migrate /usr/local/bin/migrate /usr/local/bin/migrate
COPY --from=api --chown=0:0 --chmod=0755 /app/migrate-entrypoint.sh /usr/local/bin/openctem-migrate
# Bind :443 (and the optional :80 redirect) as non-root, on Kubernetes too:
# the file capability is set in the caddy stage and COPY keeps it (setting it
# here would store the binary a second time in a new layer).
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
# The writable paths, owned by the runtime user: /data and /config (see VOLUME
# below), and the Next.js cache (.next/cache, the only place the web server
# writes besides /tmp).
RUN ln -s server /opt/openctem/api/bootstrap-admin \
 && mkdir -p /data/ca /config /certs /opt/openctem/web/.next/cache /opt/openctem/console/console/.next/cache \
 && chown nextjs:nodejs /data /data/ca /config /opt/openctem/web/.next/cache /opt/openctem/console/console/.next/cache

# The gateway: api/deploy/gateway (Caddyfile + planes.caddy + modes/ + sensors/ + entrypoint.sh).
# sensors/ holds the layer-4 sensor routing the Caddyfile imports; this image's
# Caddy has no layer4 module, so only OPENCTEM_SENSOR_GATEWAY=off applies here.
COPY --from=gateway Caddyfile planes.caddy /etc/caddy/
COPY --from=gateway --chmod=0755 entrypoint.sh /etc/caddy/
COPY --from=gateway modes /etc/caddy/modes
COPY --from=gateway sensors /etc/caddy/sensors
COPY --from=gateway admin /etc/caddy/admin
COPY --chmod=0755 supervise.sh /usr/local/bin/openctem-supervise
COPY --chmod=0644 console-plan.sh /usr/local/bin/openctem-console-plan
COPY --chmod=0755 healthcheck.sh /usr/local/bin/openctem-healthcheck

ENV GATEWAY=on \
    MIGRATE_ON_START=true \
    NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    BACKEND_API_URL=http://127.0.0.1:8080 \
    STORAGE_LOCAL_PATH=/data/attachments \
    SENSOR_MTLS_CA_DIR=/data/sensor-ca \
    XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config \
    OPENCTEM_TLS_MODE=internal \
    OPENCTEM_GATEWAY_DIR=/etc/caddy \
    OPENCTEM_CA_EXPORT_DIR=/data/ca \
    OPENCTEM_CERT_DIR=/certs \
    OPENCTEM_API_UPSTREAM=127.0.0.1:8080 \
    OPENCTEM_WEB_UPSTREAM=127.0.0.1:3000 \
    OPENCTEM_CONSOLE_UPSTREAM=127.0.0.1:3001 \
    OPENCTEM_ADMIN_SITE=port \
    ADMIN_LISTEN_ADDR=127.0.0.1:8081

# /data holds uploaded attachments (STORAGE_LOCAL_PATH), the gateway's internal
# CA + certificates (and ACME account), and /data/ca/openctem-root-ca.crt, the
# root sensors trust in TLS mode `internal`. Keep it on a volume: without it
# every restart loses attachments and mints a new CA, and sensors stop trusting
# the gateway.
VOLUME ["/data"]
# GATEWAY=on publishes 443 and the platform console's site on 8443
# (OPENCTEM_ADMIN_SITE=port, private client networks only; 80 is an optional
# http->https redirect, the same as api/deploy/docker-compose.http-redirect.yml).
# GATEWAY=off: 8080 (API) and 3000 (web). The console is not started (it
# listens on loopback only, and only the gateway forwards the client address
# the API's admin network check needs); OPENCTEM_CONSOLE_STANDALONE=true starts
# it on 127.0.0.1:3001 for an operator who fronts it in the same network
# namespace. Never publish 3001.
EXPOSE 443 8443
USER nextjs
WORKDIR /opt/openctem

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
  CMD ["/usr/local/bin/openctem-healthcheck"]

# tini is PID 1: reaps zombies and forwards SIGTERM to the supervisor, which
# forwards it to every child and waits.
ENTRYPOINT ["/sbin/tini", "-g", "--", "/usr/local/bin/openctem-supervise"]

LABEL org.opencontainers.image.title="OpenCTEM (all-in-one)" \
      org.opencontainers.image.description="OpenCTEM API + web console + platform console + gateway in one container; Postgres and Redis external" \
      org.opencontainers.image.source="https://github.com/openctemio/openctem" \
      org.opencontainers.image.licenses="GPL-3.0-only"
