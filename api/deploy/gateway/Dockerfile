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
ARG GO_IMAGE=golang:1.26.9-alpine
ARG BASE_IMAGE=alpine:3.24

FROM ${GO_IMAGE} AS build
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
 && /usr/bin/caddy list-modules | grep -qx layer4 \
 && apk add --no-cache libcap-setcap \
 && setcap cap_net_bind_service=+ep /usr/bin/caddy

FROM ${BASE_IMAGE}
# mailcap: /etc/mime.types for file responses, as in the Caddy image.
RUN apk add --no-cache ca-certificates mailcap \
 && mkdir -p /config/caddy /data/caddy /etc/caddy /usr/share/caddy /srv
# The bind capability (ports 80/443) is set in the build stage; COPY keeps it.
COPY --from=build /usr/bin/caddy /usr/bin/caddy
ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data
EXPOSE 80 443 443/udp 2019
WORKDIR /srv
# Root, as in the Caddy image this replaces: operators' existing gateway-data
# and gateway-config volumes hold root-owned files, so a non-root gateway
# needs a one-time ownership change of those volumes first (it binds 443
# through the file capability above, not through root).
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
