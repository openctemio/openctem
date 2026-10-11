### Added: sensors reach the gRPC binding on the API's own port without a gateway

- With `SERVER_TLS_CERT_FILE` and `SERVER_TLS_KEY_FILE` set, the API listener terminates TLS itself. A TLS connection that offers the sensor ALPN id `openctem-sensor/3` is served by the sensor gRPC binding on that same port, with the same checks as the mTLS listener (client certificate from the sensor CA, resolved at the handshake and on every call); every other connection gets the configured certificate and the normal API. The endpoint is advertised automatically once the self-probe passes. For an API deployed without our gateway (web served separately, or behind a TCP load balancer), no extra port is needed.
- The certificate files are re-read when they change.
- Unset (the default), the API serves plain HTTP behind a TLS proxy as before.
- RFC-059 §5.1 now has a deployment-mode matrix, with tested nginx `stream` and HAProxy examples for ALPN routing in the architecture doc.
