### Added: the transport of each sensor (RFC-059)

- Every heartbeat records how it arrived: `grpc` (protocol v3 over mutual TLS), `https` (protocol v3 over HTTPS) or `v2`, decided by the platform from the listener the call came on, plus the sensor's own fallback reason (sanitized, 256 characters). A heartbeat carried by v3 records protocol 3. Migration 001345 adds `sensors.protocol_binding` and `protocol_fallback_reason` (nullable, no backfill).
- `GET /api/v1/sensors/{id}` and the list return them under `protocol.binding` and `protocol.fallback_reason`; the sensor detail sheet shows the transport and the reason.
