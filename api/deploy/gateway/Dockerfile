# The gateway with the layer-4 module (caddy-l4), for sensor protocol v3's
# gRPC binding on the same port 443 (docs/rfcs/RFC-059-sensor-transport-v3.md
# §5): a TLS connection that offers the sensor ALPN id (or names the dedicated
# sensor host) is passed through untouched to the API's mTLS listener; every
# other connection is terminated as before. Needed with
# OPENCTEM_SENSOR_GATEWAY=alpn or passthrough
# (docker-compose.sensor-passthrough.yml); with the stock image sensors use
# the HTTPS binding.
ARG CADDY_VERSION=2.11.4

FROM caddy:${CADDY_VERSION}-builder AS build
ARG CADDY_L4_VERSION=v0.1.2
RUN xcaddy build --with github.com/mholt/caddy-l4@${CADDY_L4_VERSION}

FROM caddy:${CADDY_VERSION}-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
