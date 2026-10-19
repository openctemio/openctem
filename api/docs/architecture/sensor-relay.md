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

**Shipped:** the relay, its wire contract, the platform's envelope
implementation and the relay connector, with operator tools for its keys
and for minting tickets. **Designed, not built yet:** ticket issuing by the
API, key distribution in the signed hello, the sensor's relay mode in
sensorkit (the transport itself is in sdk-go `pkg/relayclient`), the console
pages and store-and-forward (RFC-116 §7).

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
  realm_bytes: 536870912         # 512 MiB held per realm, both directions
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

## Relay connector (platform side)

Runs next to the API, on the private network, as
`openctem-sensor-relay connector`. It dials the relay; nothing dials it.

```
openctem-sensor-relay ingest-keygen   -out /keys/ingest.pem     # prints the public key for sensors
openctem-sensor-relay response-keygen -out /keys/response.pem   # prints the public key for sensors
openctem-sensor-relay ticket-keygen   -out /keys/ticket.pem     # prints the public key for relay.yaml
openctem-sensor-relay pin -cert connector.pem                    # pin for relay.yaml connector_pins
```

| Variable | Meaning |
|---|---|
| `CONNECTOR_RELAY_URL` | the relay's https URL |
| `CONNECTOR_RELAY_PIN` | hex SHA-256 of the relay certificate's public key (`pin -cert relay.pem`) |
| `CONNECTOR_TLS_CERT`, `CONNECTOR_TLS_KEY` | the connector's client certificate (its pin is in the relay configuration) |
| `CONNECTOR_REALM` | the realm the relay serves this connector |
| `CONNECTOR_INGEST_KEYS` | comma-separated ingest key files (two during a rotation) |
| `CONNECTOR_RESPONSE_KEY` | the response key file |
| `CONNECTOR_API_URL` | the API on the private network, e.g. `http://api:8080`; **no path prefix** (sensors sign the request path, so a prefix would break every signature; the connector refuses to start with one) |
| `CONNECTOR_HEALTH_LISTEN` | `/healthz` and `/metrics`, default `127.0.0.1:9091` |

The connector sets `X-Relay-Sensor` to the sensor id of the route each
envelope arrived on, replacing anything the sensor sent; the API refuses a
signed request whose verified signing sensor is another one.

The relay is at-least-once: a request can be delivered twice (retry after a
lost answer, connector restart). A relayed call that is not idempotent must
carry an `Idempotency-Key` header (the connector forwards it) so a route
that honours it can answer the repeat with the first result; a route that
does not honour it must be safe to repeat.

Key files are created 0400 and refused when others can read them. The
connector forwards only `/api/v2/sensor/` requests, only allowlisted
headers each way, never client-address headers or cookies.

Until the API issues tickets, an operator mints one per sensor with
`openctem-sensor-relay ticket -key /keys/ticket.pem -realm R -tenant T
-sensor S -sensor-key <base64 identity public key> -relay ID -ttl 12h`
(at most 24 h).

Metric: `openctem_relay_connector_requests_total{outcome}`.

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
