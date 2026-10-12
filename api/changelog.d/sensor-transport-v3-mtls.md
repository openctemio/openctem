### Added: sensor protocol v3 gRPC binding with mTLS (RFC-059)

- With `SENSOR_TRANSPORT_V3_ENABLED` and `SENSOR_PUBLIC_HOST` set, the API serves the gRPC binding on `SENSOR_MTLS_LISTEN_ADDR` (`:8443`): TLS 1.3, HTTP/2 only, a client certificate from the sensor CA required. The certificate's key is resolved through the sensor key table at the handshake and on every request, so a revoked key or sensor is refused without a revocation list; revoking or disabling a sensor ends its live control stream at once.
- `IssueCertificate` certifies a key-bound sensor's registered key (7 days by default, `SENSOR_MTLS_CERT_TTL`); the sensor renews it over either binding. Issuance is recorded on the sensor's timeline.
- The sensor CA comes from `SENSOR_MTLS_CA_CERT_FILE` + `SENSOR_MTLS_CA_KEY_FILE`, or is created once in `SENSOR_MTLS_CA_DIR` (default `/app/data/sensor-ca`, on the `api-data` volume). It is separate from the job signer.
