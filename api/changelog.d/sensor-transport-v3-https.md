### Added: sensor protocol v3 over HTTPS (RFC-059), off by default

- `SENSOR_TRANSPORT_V3_ENABLED=true` serves `openctem.sensor.v3.SensorService` (Connect, gRPC and gRPC-Web) under `/api/v3/sensor`, authenticated by an RFC 9421 signature of a key-bound sensor only (no bearer keys). Every call runs through the protocol v2 routes in-process: same validation, limits and side effects; the v2 rate budgets are shared by both protocols.
- `Subscribe` is a control stream: the doorbell is pushed when a command becomes pending or a held one is cancelled (under a second on one replica), with a keepalive; a revoked key or sensor ends it.
- The v2 hello lists `transport_v3` (HTTPS path, `SENSOR_PUBLIC_HOST`) when v3 is on. The gateway routes `/api/v3/sensor/*` to the API (sensor plane).
