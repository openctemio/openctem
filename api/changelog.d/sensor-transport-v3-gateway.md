### Added: sensor protocol v3 gRPC binding on port 443 by SNI (Compose)

- `deploy/docker-compose.sensor-passthrough.yml` builds the gateway with the layer4 module and passes TLS for `SENSOR_PUBLIC_HOSTNAME` through to the API's mTLS listener with a PROXY protocol v2 header; every other host is served as before. The API believes PROXY headers only from `SENSOR_MTLS_TRUSTED_PROXIES` (the gateway) and closes a connection that sends one from anywhere else.
- **Upgrade note:** nothing changes without the override. To use it: point a DNS name (different from the platform host) at the gateway, then `SENSOR_PUBLIC_HOSTNAME=<name> docker compose -f docker-compose.yml -f docker-compose.sensor-passthrough.yml up -d --build`.
