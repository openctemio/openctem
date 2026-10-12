### Security: the sensor protocol v3 HTTPS binding keeps the per-IP rate limit and bounds calls in flight

- The v3 HTTPS binding (`/api/v3/sensor`, served when `SENSOR_TRANSPORT_V3_ENABLED` is on) is mounted ahead of the router, so it skipped every global guard, the per-IP rate limit included. A request with a made-up signature cost a database lookup, without credentials and without limit. The binding now keeps the per-IP rate limit, and at most 256 unary calls per replica are in flight across both v3 bindings before authentication runs (`503` with `Retry-After` beyond).
- A control stream's connection deadlines are lifted only after it authenticated, and a unary call on the gRPC binding must deliver its message within the unary timeout.
- A sensor's key use (last seen, last address, key last used) is written at most once per 15 seconds per sensor and address, instead of two writes per request.
