### Behaviour change: sensor transport status moved to Console > Operations

- The sensor transport status (protocol v3 mode, gRPC self-probe state, endpoint and reason) is installation infrastructure: it is now part of `GET /api/v1/admin/operations` (`sensor_transport`, platform admins only) and shown on Console > Operations as a calm note in plain language, with a link to the transport docs, only when an operator can change something.
- Removed `GET /api/v1/sensors/transport`: organization members no longer see the platform's gRPC endpoint or probe reason on the Sensors page.
- Sensor detail: the transport line labels HTTPS as "HTTPS" and explains each sensor fallback reason (including `platform_unreachable`) in plain words, with the reason code in a tooltip; the text is translated (en, vi).
