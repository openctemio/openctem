### Security: the sensor control plane has a per-organization budget

- Heartbeats, polls, claims, command transitions, logs, manifests and fingerprint queries were limited per sensor only, so an organization with many sensors multiplied that budget without bound. They now also share a per-organization budget of 500 requests per second (burst 1000) per API replica, on protocol v2 and v3 alike, sized well above what a large fleet sends. Over it, a sensor gets `429 rate-limited` with `Retry-After` and retries.
