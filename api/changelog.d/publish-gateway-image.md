### Added: the layer4 gateway image is published

- Releases publish `ghcr.io/openctemio/openctem-gateway` (the `api/deploy/gateway` Caddy with the layer4 module). With `OPENCTEM_SENSOR_GATEWAY=alpn` it lets sensors use gRPC with mutual TLS on port 443 next to the web UI; operators no longer build it themselves.
