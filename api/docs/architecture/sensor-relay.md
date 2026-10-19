# Sensor relay

> Design: [RFC-116](../rfcs/RFC-116-sensor-relay.md). Code: `cmd/sensor-relay`
> (binary), `internal/sensorrelay` (server, mailboxes, metrics),
> `pkg/sensorproto/relay` (tickets, batch framing). Sensor side: sdk-go
> `pkg/sealedmsg`.

The relay lets a sensor that cannot reach the platform (a sensor on the
internet, a platform inside a private network) work through a broker that
both sides dial out to. It carries sealed envelopes it cannot read: the
sensor's signed request sealed to the platform's ingest key, and the
platform's signed response sealed to the sensor's key.

**Shipped:** the relay itself and its wire contract. **Designed, not built
yet:** the platform's relay connector, ticket issuing, key distribution, the
sensor's relay transport, the console pages and store-and-forward
(RFC-116 §7). Until the connector ships, a relay has no platform side to
talk to.

## Flow

```
 sensor ──TLS 1.3, client cert = identity key, ticket──▶ sensor-relay ◀──TLS 1.3, pinned client cert── relay connector
   POST /v1/sensor/up        sealed request ─────────▶ realm queue ─────▶ GET /v1/connector/up?wait=25
   GET  /v1/sensor/down?wait=25  ◀──── sensor mailbox ◀──── POST /v1/connector/down/{sensor}  sealed response
```

- A **sensor** is admitted when its ticket verifies under the realm's ticket
  keys, names this relay, is within its validity (≤ 24 h, 2 min skew), and
  its key equals the TLS client certificate's key. Its mailbox comes from
  the ticket only.
- A **connector** is admitted when the SHA-256 of its certificate's
  SubjectPublicKeyInfo is pinned for a realm; it sees only that realm.
- Every connection must present a client certificate (TLS 1.3 only).

## Configuration

```yaml
relay_id: relay-1                # tickets must name it
realms:
  - name: acme-prod
    ticket_keys: ["<base64 Ed25519 public key>"]       # two during a rotation
    connector_pins: ["<hex sha256 of the connector SPKI>"]
limits:                          # all optional; defaults shown
  mailbox_items: 64
  mailbox_bytes: 67108864        # 64 MiB per mailbox
  total_bytes: 2147483648        # 2 GiB held in total
  ttl: 10m
  sensor_rate: 10                # requests per second per sensor
  sensor_burst: 20
  max_wait: 25s
  max_polls_per_sensor: 2
```

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_CONFIG` | `/etc/openctem-relay/relay.yaml` | the file above |
| `RELAY_LISTEN` | `:8443` | the TLS listener sensors and connectors reach |
| `RELAY_TLS_CERT`, `RELAY_TLS_KEY` | (required) | the relay's server certificate |
| `RELAY_HEALTH_LISTEN` | `127.0.0.1:9090` | `/healthz` and `/metrics`; never expose it |

`openctem-sensor-relay check` validates the configuration;
`openctem-sensor-relay pin -cert connector.pem` prints the pin to configure.

## Limits and behaviour

| Situation | Answer |
|---|---|
| Mailbox or total cap reached | 429, `Retry-After: 5` |
| Sensor over its request rate | 429, `Retry-After: 1` |
| Third concurrent poll of one sensor | 429 |
| Envelope over 16 MiB + 64 KiB | 413 |
| Ticket or connector not accepted | 401, the same body for every reason |
| Envelope not claimed within the TTL | dropped, counted as `expired` |
| Relay restart | in-flight envelopes are lost; both sides retry |

## Metrics

`openctem_relay_envelopes_total{direction,outcome}`,
`openctem_relay_auth_failures_total{side}`, `openctem_relay_bytes_held`,
`openctem_relay_sensor_polls`. Labels never carry a realm, tenant or sensor
id.

## Security notes

- The relay holds no key that opens an envelope and no key that signs a
  ticket; a compromised relay can delay or drop traffic, nothing else.
- Logs carry counts and outcomes; auth failures are logged at debug level
  with the claimed realm only.
- Run it as a non-root user in a minimal image; it makes no outbound
  connections.
