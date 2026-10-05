### Security: key-bound sensor identity (signed requests, no bearer key)

- Sensors can now authenticate with their own Ed25519 key: every request carries an RFC 9421 signature (narrow profile: method, path, query and Content-Digest, single-use nonce, 5-minute window) verified on both protocol v1 and v2 routes before the bearer-key path. A signed request is decided by its signature alone and never falls back to a bearer key (RFC-052).
- A key-bound sensor has no bearer key and cannot renew into one; its public keys live in the new `sensor_keys` table and revocation applies on the next request. Migration **001065** adds `sensor_keys` and `sensors.auth_kind` (existing sensors stay `bearer`; nothing changes for them).
- Pairing (how a sensor gets such a key) follows in the next change.
