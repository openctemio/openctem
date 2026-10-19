# RFC-116: Sensor relay and sealed envelopes

| | |
|---|---|
| Status | Accepted (2026-10-19). Partly implemented: the relay (`cmd/sensor-relay`, `internal/sensorrelay`) and its wire contract (`pkg/sensorproto/relay`: tickets, batch framing) have shipped; the sensor-side envelope and local store are in sdk-go (`pkg/sealedmsg`, `pkg/localstore`). Designed: the platform relay connector, ticket issuing, key distribution in the signed hello, the pairing bundle and the console, store-and-forward (§8) |
| Scope | api (`cmd/sensor-relay`, `internal/sensorrelay`, `pkg/sensorproto/relay`; later the relay connector in the sensor-gateway role, `pkg/sensorproto/sealed`, relay tickets, encryption-key registration, hello fields), web (relays settings, pairing wizard mode step, sensor connection state), sdk-go (`pkg/sealedmsg`, relay transport, `pkg/localstore`) |
| Related | RFC-040 (mutual distrust, sensor-gateway role), RFC-052 (pairing), RFC-030 (scan distribution), RFC-035 (heartbeat), RFC-061 (content packs), RFC-100 (shared sensors); `docs/architecture/sensor-relay.md` |

## 1. Problem

Every sensor connection is direct today: the sensor dials the platform URL
(v3 gRPC with mTLS, v2 HTTPS as the fallback). A self-hosted platform is
often reachable only inside the customer's network, while the sensors that
map the external attack surface run on the internet. Those sensors cannot
pair or work at all. Some networks allow egress only through a proxy or only
to object storage. The answer must not give a new intermediary the power to
read results or credentials, alter jobs, or impersonate either side.

## 2. Options

| Option | Verdict |
|---|---|
| Open the platform to the internet | refused by the customers who need this most |
| Platform dials the sensor (sensor listens) | needs an inbound port on every sensor; kept for later, on request, as the connector dialling a relay embedded in the sensor |
| Customer tunnel or overlay VPN | works today as direct mode over the tunnel; documented, not built |
| **Relay both sides dial out to, carrying end-to-end sealed envelopes** | **chosen**: no inbound port on either side; the relay is untrusted by design |
| Store-and-forward through object storage | same envelopes on a different mailbox backend, for networks that allow only storage egress (§8) |

## 3. Design

### 3.1 Sealed envelope

The sensor builds exactly the v2 request it builds for a direct connection
(RFC 9421 signature, nonce, `Content-Digest`) and seals it with HPKE
(RFC 9180, base mode) to the platform's **ingest key**. The suite is the
hybrid KEM ML-KEM-768 + X25519, HKDF-SHA256 and ChaCha20-Poly1305: relayed
traffic can be recorded, and credentials and findings stay sensitive for
years. The platform's response is signed with its **response key** (Ed25519;
HPKE base mode does not authenticate the sender), bound to the SHA-256 of the
request envelope, the realm and the sensor id, and sealed to the sensor's
**encryption key**. The header and the route (realm, sensor) are bound into
the HPKE info. Wire format and test vector: sdk-go `pkg/sealedmsg`.

Because the inner request is the unchanged v2 request, the platform needs no
new handlers: the relay connector replays it to the local v2 API, where the
signature, nonce, clock, rate and tenant checks run as for a direct sensor.

### 3.2 Relay

A small stateless binary. Sensors and the realm's relay connector both
connect over TLS 1.3 with a client certificate:

- a **sensor** presents a certificate holding its Ed25519 identity key and a
  **ticket** the platform signed (`realm, tenant, sensor, key, relay, iat,
  exp ≤ 24 h`). The relay verifies the ticket with the realm's pinned ticket
  keys, checks that it names this relay, and checks that its key is the
  certificate's key. The mailbox is `(realm, sensor)` from the ticket;
- a **connector** presents a certificate whose SubjectPublicKeyInfo hash is
  pinned for exactly one realm, and sees only that realm.

| Endpoint | Who | What |
|---|---|---|
| `POST /v1/sensor/up` | sensor | queue one envelope for the realm's connector (202) |
| `GET /v1/sensor/down?wait=s` | sensor | long-poll its own mailbox: a framed batch (200) or nothing (204) |
| `GET /v1/connector/up?wait=s` | connector | long-poll the realm's queue: a framed batch with each envelope's sensor id |
| `POST /v1/connector/down/{sensor}` | connector | queue one envelope for a sensor of its realm |

Quotas (defaults): 64 envelopes and 64 MiB per mailbox, 2 GiB in total, 512 MiB per realm,
10 requests/s burst 20 per sensor, 2 open polls per sensor, envelope ≤
16 MiB + 64 KiB, waits ≤ 25 s, TTL 10 min. Over a quota: 429 with
Retry-After, decided from the announced Content-Length before the body is
read (a body of unknown length counts as a full envelope). Nothing is written to disk; a restart loses in-flight envelopes,
and both sides retry (the outbox makes results at-least-once; the platform
deduplicates by report id). Logs and metrics carry directions, outcomes,
counts and sizes, never envelope bytes, paths or ids as metric labels.

### 3.3 Keys

| Key | Holder | Delivered |
|---|---|---|
| Sensor identity (Ed25519) | sensor | exists (RFC-052) |
| Sensor encryption key (HPKE) | sensor, sealed in its local store | generated at pairing; public part registered by a signed request |
| Platform ingest key (HPKE) | relay connector only | pairing bundle and signed hello; rotation by key id |
| Platform response key (Ed25519) | relay connector only | pairing bundle and signed hello |
| Relay ticket key (Ed25519) | platform | its public key is pinned in the relay configuration |
| Relay TLS certificate, connector certificate | relay, connector | relay install; the relay's SPKI pin is in the pairing bundle |

### 3.4 Pairing bundle

For a relay or store-and-forward sensor the console's pairing wizard
produces a bundle signed by the platform: realm, relay URL and SPKI pin,
ingest and response public keys, the job-signer root fingerprint, a
one-time pairing token (≤ 1 h), expiry. The administrator moves it to the
sensor over a channel they trust. Pairing (RFC-052, SAS included) then runs
through the relay; the relay admits ticket-less connections only with a
valid pairing token at a low rate.

### 3.5 Fallback

v3 gRPC → v2 HTTPS → relay (when paired with one) → store-and-forward (when
configured). A step down needs 3 consecutive transport failures over at
least 2 minutes; the higher steps are probed again every 10 minutes with
jitter. Each change is reported on the heartbeat (`transport.mode`,
`fallback_reason`) and shown on the sensor page.

## 4. Threat model

| Actor | Can | Cannot |
|---|---|---|
| Relay operator, compromised relay, our hosted relay | delay or drop envelopes; see realm, sensor ids, sizes and timing | read or alter envelopes; move them to another sensor; answer as the platform; replay requests (nonce) or responses (digest binding, ±10 min); reach another realm |
| Network attacker before the relay | as above, less | anything beyond drop or delay (mTLS + end-to-end) |
| Another sensor | use its own mailbox | use another sensor's ticket without that sensor's key; read another mailbox |
| Another realm's connector | its own realm | see or feed another realm's mailboxes |
| Hostile tenant on a hosted relay | exhaust its own quotas | exhaust others (per-sensor quotas, total cap, per-sensor rate) |
| Compromised platform | what it can already do directly | nothing more through the relay |

## 5. Decisions

| # | Decision |
|---|---|
| D1 | One sealed-mailbox mechanism for relay and store-and-forward; the inner request is the unchanged v2 request |
| D2 | HPKE with the hybrid ML-KEM-768 + X25519 KEM from the Go standard library |
| D3 | The relay is stateless and untrusted; routing comes from platform-signed tickets bound to the sensor's TLS key |
| D4 | Platform-initiated pull only when a customer asks for it |

## 6. Operations

`openctem-sensor-relay serve | check | pin -cert FILE`; configuration in YAML
(`RELAY_CONFIG`), TLS certificate `RELAY_TLS_CERT`/`RELAY_TLS_KEY`, listener
`RELAY_LISTEN` (`:8443`), health and metrics on `RELAY_HEALTH_LISTEN`
(`127.0.0.1:9090`, never exposed). Details: `docs/architecture/sensor-relay.md`.

## 7. Implementation

| Part | State |
|---|---|
| Relay binary, mailboxes, quotas, metrics (`cmd/sensor-relay`, `internal/sensorrelay`) | shipped |
| Wire contract: tickets, batch framing (`pkg/sensorproto/relay`) | shipped |
| Sensor envelope (`sdk-go pkg/sealedmsg`), local store (`sdk-go pkg/localstore`) | opened in sdk-go |
| Relay connector in the sensor-gateway role, `pkg/sensorproto/sealed`, ingest and response keys | designed |
| Ticket issuing (`POST /api/v2/sensor/relay-ticket`), encryption-key registration, hello fields | designed |
| Sensor relay transport and fallback chain (sdk-go) | designed |
| Console: relays settings, pairing wizard mode step, connection state | designed |
| Store-and-forward backend | designed |

## 8. Later

Store-and-forward uses the same envelopes as objects under per-sensor
prefixes, with a persistent seen-set of request ids for a window of up to
1 hour (the signed-job validity). Platform-initiated pull is the connector
dialling a relay embedded in the sensor.
