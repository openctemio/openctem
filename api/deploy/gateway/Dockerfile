# syntax=docker/dockerfile:1
# The gateway with the layer-4 module (caddy-l4), for sensor protocol v3's
# gRPC binding on the same port 443 (docs/rfcs/RFC-059-sensor-transport-v3.md
# §5): a TLS connection that offers the sensor ALPN id (or names the dedicated
# sensor host) is passed through untouched to the API's mTLS listener; every
# other connection is terminated as before. Needed with
# OPENCTEM_SENSOR_GATEWAY=alpn or passthrough
# (docker-compose.sensor-passthrough.yml); with the stock image sensors use
# the HTTPS binding.
#
# Caddy is compiled here with the pinned Go toolchain (not the toolchain the
# Caddy release was built with, whose standard-library advisories the
# released binary carries), and the runtime is plain Alpine laid out like the
# Caddy image (XDG_CONFIG_HOME=/config, XDG_DATA_HOME=/data, /etc/caddy,
# /srv), with ONE caddy binary: building on the Caddy image and replacing its
# binary shipped both.
# Base images are pinned by digest in the FROM lines themselves, where
# Dependabot finds and refreshes them (it does not read ARG defaults).
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ARG CADDY_VERSION=v2.11.4
ARG CADDY_L4_VERSION=v0.1.2
# Dependencies with security fixes newer than the Caddy release; drop an entry
# once a Caddy release requires that version itself.
ARG CADDY_DEPS="golang.org/x/net@v0.60.0 google.golang.org/grpc@v1.83.2"
WORKDIR /src
RUN printf '%s\n' 'package main' \
      'import (' \
      '	caddycmd "github.com/caddyserver/caddy/v2/cmd"' \
      '	_ "github.com/caddyserver/caddy/v2/modules/standard"' \
      '	_ "github.com/mholt/caddy-l4"' \
      ')' \
      'func main() { caddycmd.Main() }' > main.go \
 && go mod init openctem.local/gateway \
 && go get "github.com/caddyserver/caddy/v2@${CADDY_VERSION}" \
      "github.com/mholt/caddy-l4@${CADDY_L4_VERSION}" ${CADDY_DEPS} \
 && go mod tidy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/bin/caddy . \
 && /usr/bin/caddy version | grep -q "^${CADDY_VERSION} " \
 && /usr/bin/caddy list-modules | grep -qx layer4

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# mailcap: /etc/mime.types for file responses, as in the Caddy image.
# The gateway runs as uid/gid 1000 (as in the Helm chart). /data and /config
# belong to it, so a new named volume mounted there starts with that owner.
RUN apk add --no-cache ca-certificates mailcap \
 && addgroup -S -g 1000 caddy && adduser -S -D -H -u 1000 -G caddy -h /data caddy \
 && mkdir -p /config/caddy /data/caddy /etc/caddy /usr/share/caddy /srv \
 && chown -R 1000:1000 /config /data
# No file capability on caddy: a binary with one cannot be executed under
# no-new-privileges with every capability dropped (how Compose runs it), and
# it would need NET_BIND_SERVICE kept. The gateway binds 443/80 as non-root
# through the namespaced sysctl net.ipv4.ip_unprivileged_port_start=0 instead
# (Compose sets it; on Kubernetes it is a "safe" sysctl).
COPY --from=build /usr/bin/caddy /usr/bin/caddy
ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data
EXPOSE 80 443 443/udp 2019
WORKDIR /srv
LABEL org.opencontainers.image.title="OpenCTEM gateway" \
      org.opencontainers.image.description="OpenCTEM gateway: Caddy with the layer4 module (non-root)" \
      org.opencontainers.image.source="https://github.com/openctemio/openctem" \
      org.opencontainers.image.licenses="GPL-3.0-only"
# Caddy's admin API answers on 127.0.0.1:2019 (the shared Caddyfile).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:2019/config/"]
# Non-root (uid 1000); needs net.ipv4.ip_unprivileged_port_start=0 to bind
# 443/80, or a non-privileged port. Volumes written by an older gateway
# that ran as root need a one-time `chown -R 1000:1000` (entrypoint.sh says so
# and api/deploy/docker-compose.yml does it in its gateway-init service).
USER 1000:1000
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
