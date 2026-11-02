### Added: sensors reach a platform behind a private CA by pinning its root

- `PLATFORM_CA_CERT_FILE`: the PEM bundle of the CA certificate(s) that sign the platform's TLS certificate. The API parses it at startup and re-reads it when it changes; a file that holds a private key is refused as a whole (logged), and only CA certificates are kept.
- `GET /api/v1/sensors/platform-ca` serves that bundle: public, the same for every organization, certificates only (`application/x-pem-file`, `Cache-Control: public, max-age=300`), rate limited per IP, 404 when no CA is configured.
- Every install command pins the CA's root as `SENSOR_CA_SHA256` (docker run, Compose, Kubernetes, Linux service, Helm, env), so a sensor that does not trust the platform's chain fetches the bundle and trusts only a matching root that signs the chain. Install answers carry `platform_ca` (each certificate's name, SHA-256, root or intermediate, expiry; the pin; the download path).
- The Add sensor dialog shows the CA's certificates with their SHA-256, the pinned root and a download, and offers a fifth choice, several sensors on one host, with the multi-sensor kit's `sensors.sh add ... --ca-sha256` command.
- Guide: `docs/how-to/sensors-behind-a-private-ca.md`.

### Deprecated: SENSOR_CA_CERT_FILE on the API

- The API's `SENSOR_CA_CERT_FILE` is now `PLATFORM_CA_CERT_FILE`; the old name is read only when the new one is unset, and startup warns. On a sensor host `SENSOR_CA_CERT_FILE` keeps its meaning.
- **Upgrade note:** rename `SENSOR_CA_CERT_FILE` to `PLATFORM_CA_CERT_FILE` in the API's environment (the bundled `deploy/docker-compose.yml` does it already).
