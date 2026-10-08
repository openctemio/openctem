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
ARG GO_IMAGE=golang:1.26.8-alpine
# Same Caddy as the split deployment (api/deploy/docker-compose.yml CADDY_VERSION).
ARG CADDY_IMAGE=caddy:2.11.4-alpine

FROM ${API_IMAGE} AS api
FROM ${WEB_IMAGE} AS web
FROM ${CADDY_IMAGE} AS caddy

# golang-migrate, same version as CI (api-ci.yml). Built in the target
# platform's own stage, so no arch-specific download URL to get wrong.
FROM ${GO_IMAGE} AS migrate
RUN CGO_ENABLED=0 go install -ldflags="-s -w" -tags postgres \
      github.com/golang-migrate/migrate/v4/cmd/migrate@v4.18.1 \
 && cp "$(go env GOPATH)/bin/migrate" /usr/local/bin/migrate

# Final image: the web image's base (node, alpine) is the only runtime with a
# language VM; the API, migrate and Caddy are static binaries.
FROM web AS final
USER root
RUN apk add --no-cache tini bash ca-certificates tzdata libcap wget postgresql17-client \
 && mkdir -p /opt/openctem/api /opt/openctem/web /data/ca /config /certs /etc/caddy

# web: the standalone Next.js server as built by web/Dockerfile (WORKDIR /app there)
RUN cp -a /app/. /opt/openctem/web/ && rm -rf /app
# api: server + admin tool + migrations + configs (WORKDIR /app in api/Dockerfile)
COPY --from=api /app/server /app/bootstrap-admin /opt/openctem/api/
COPY --from=api /app/migrations /opt/openctem/api/migrations
COPY --from=api /app/configs /opt/openctem/api/configs
COPY --from=migrate /usr/local/bin/migrate /usr/local/bin/migrate
COPY --from=api /app/migrate-entrypoint.sh /usr/local/bin/openctem-migrate
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
# Bind :443 (and the optional :80 redirect) as non-root, on Kubernetes too.
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy

# The gateway: api/deploy/gateway (Caddyfile + planes.caddy + modes/ + sensors/ + entrypoint.sh).
# sensors/ holds the layer-4 sensor routing the Caddyfile imports; this image's
# Caddy has no layer4 module, so only OPENCTEM_SENSOR_GATEWAY=off applies here.
COPY --from=gateway Caddyfile planes.caddy entrypoint.sh /etc/caddy/
COPY --from=gateway modes /etc/caddy/modes
COPY --from=gateway sensors /etc/caddy/sensors
COPY supervise.sh /usr/local/bin/openctem-supervise
COPY healthcheck.sh /usr/local/bin/openctem-healthcheck
RUN chmod 0755 /usr/local/bin/openctem-supervise /usr/local/bin/openctem-healthcheck /usr/local/bin/openctem-migrate /etc/caddy/entrypoint.sh \
 && chown -R nextjs:nodejs /opt/openctem /data /config

ENV GATEWAY=on \
    MIGRATE_ON_START=true \
    NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    BACKEND_API_URL=http://127.0.0.1:8080 \
    STORAGE_LOCAL_PATH=/data/attachments \
    XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config \
    OPENCTEM_TLS_MODE=internal \
    OPENCTEM_GATEWAY_DIR=/etc/caddy \
    OPENCTEM_CA_EXPORT_DIR=/data/ca \
    OPENCTEM_CERT_DIR=/certs \
    OPENCTEM_API_UPSTREAM=127.0.0.1:8080 \
    OPENCTEM_WEB_UPSTREAM=127.0.0.1:3000

# /data holds uploaded attachments (STORAGE_LOCAL_PATH), the gateway's internal
# CA + certificates (and ACME account), and /data/ca/openctem-root-ca.crt, the
# root sensors trust in TLS mode `internal`. Keep it on a volume: without it
# every restart loses attachments and mints a new CA, and sensors stop trusting
# the gateway.
VOLUME ["/data"]
# GATEWAY=on publishes 443 only (80 is an optional http->https redirect, the
# same as api/deploy/docker-compose.http-redirect.yml). GATEWAY=off: 8080 + 3000.
EXPOSE 443
USER nextjs
WORKDIR /opt/openctem

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
  CMD ["/usr/local/bin/openctem-healthcheck"]

# tini is PID 1: reaps zombies and forwards SIGTERM to the supervisor, which
# forwards it to every child and waits.
ENTRYPOINT ["/sbin/tini", "-g", "--", "/usr/local/bin/openctem-supervise"]

LABEL org.opencontainers.image.title="OpenCTEM (all-in-one)" \
      org.opencontainers.image.description="OpenCTEM API + web console + gateway in one container; Postgres and Redis external" \
      org.opencontainers.image.source="https://github.com/openctemio/openctem" \
      org.opencontainers.image.licenses="GPL-3.0-only"
