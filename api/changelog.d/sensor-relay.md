### Added: sensor relay for sensors that cannot reach the platform

- New binary `openctem-sensor-relay` (`cmd/sensor-relay`). It is a small stateless broker that sensors and the platform's relay connector both dial out to, so a sensor on the internet can work for a platform that is only reachable inside a private network. It carries sealed envelopes it cannot read, alter or answer (RFC-116).
- A sensor is admitted with a TLS client certificate holding its identity key and a platform-signed ticket for that key, that relay and one realm. A connector is admitted by a certificate pinned for one realm. Mailboxes come from the ticket, never from the request.
- Everything is held in memory under per-sensor and total quotas, with a 10-minute TTL. Metrics and logs carry outcomes and sizes only.
- The platform side (relay connector, ticket issuing, keys in the signed hello, console pages) is designed and not yet built, so a relay cannot carry traffic yet. Nothing changes for existing installations.
