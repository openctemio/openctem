### Fixed: the compose bundled sensor reaches the platform over https through the gateway

- `docker-compose.sensor.yml` pointed the bundled sensor at `http://api:8080`. Sensor releases built on sdk-go v0.35.0 and later refuse plain http to a host that is not loopback, so the sensor crash-looped as soon as `SENSOR_VERSION` was raised. The sensor now uses `https://${OPENCTEM_HOSTNAME}` and trusts the gateway's internal CA from `./ca` (`SENSOR_CA_CERT_FILE`; set it empty when the gateway uses a publicly trusted certificate).
- The gateway, not the API, is now the second member of `sensor-net` (under the name `OPENCTEM_HOSTNAME`). The sensor can no longer resolve the API service; the API is no longer attached to `sensor-net`.
- **Upgrade note:** `OPENCTEM_HOSTNAME` must be a DNS name for the sensor to find the gateway on `sensor-net`; run `docker compose -f docker-compose.yml -f docker-compose.sensor.yml up -d` again. The sensor keeps its identity in `sensor-data`.
