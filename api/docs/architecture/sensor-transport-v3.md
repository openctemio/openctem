# Sensor transport v3

Design: [RFC-059](../rfcs/RFC-059-sensor-transport-v3.md). This page says what
is built, where it lives and how to work on it.

## What is built

| Part | State | Where |
|---|---|---|
| Proto `openctem.sensor.v3.SensorService` | built | `api/proto/openctem/sensor/v3/sensor.proto` |
| Generated Go (protobuf + Connect) | built, committed | `api/pkg/sensorproto/v3`, `api/pkg/sensorproto/v3/sensorv3connect` |
| CI: buf lint, buf breaking, generated code current | built | `api/scripts/check-proto.sh`, step "Sensor Protocol v3" of API CI |
| HTTPS binding (`/api/v3/sensor`) | built, behind `SENSOR_TRANSPORT_V3_ENABLED` | `internal/infra/sensortransport` (server), `handler/sensor_v3_bridge.go` (identity, in-process authenticator, stream hints), `routes/sensor_v2.go` (`sensorV2InProcess`) |
| Control stream `Subscribe`, push on command changes (one replica) | built | `sensortransport/subscribe.go`, `postgres/command_notify.go` |
| Sensor CA, `IssueCertificate`, mTLS listener (gRPC binding), revocation | built | `sensortransport/ca.go`, `issuer.go`, `mtls.go`; `SensorService.SetStatusNotifier` |
| Redis wake fan-out across replicas | built | `internal/infra/redis/sensor_wake.go` (`SensorWakeBus`, channel `sensor:v3:wake`) |
| Gateway SNI passthrough (Compose), PROXY protocol | built | `deploy/gateway/Dockerfile`, `deploy/gateway/sensors/*.wrappers`, `deploy/docker-compose.sensor-passthrough.yml`; `SENSOR_MTLS_TRUSTED_PROXIES` |

## How a call is served

```
sensor ── POST /api/v3/sensor/openctem.sensor.v3.SensorService/<Rpc> (Connect or gRPC)
  │  Server.MountPrefix: ahead of the router (its global request timeout and
  │  buffered writers would cut the control stream); POST only, body limit
  ▼
SensorResultsV2Handler.AuthenticateV3    RFC 9421 signature of a key-bound sensor; nothing else
  ▼                                      (no bearer key, no user token); identity + peer → context
sensortransport.Server                   interceptor: identity present, tenant sensor, unary timeout
  │  RPC → v2 request (method, path, headers from the typed envelope; ids validated as UUIDs)
  ▼
in-process v2 route group               same routes, edge chain and budgets as /api/v2/sensor,
(routes.sensorV2InProcess)              behind handler.AuthenticateInProcess (identity from context,
  │                                      paused sensors only reach heartbeat and hello)
  ▼
v2 answer → v3 response, or a Connect error with the RFC 9457 problem as a Problem detail
```

The v2 budgets (per sensor, per tenant) are one set shared by both
protocols, so a sensor cannot double its budget; v3 calls are counted in the
v2 route metrics.

`Subscribe` is served by the server itself: it registers in the hub, sends
the doorbell (the heartbeat's pending jobs, actions, cancel ids and config
version, computed by `SensorControlV2Handler.StreamHints`), then waits for a
wake (a command of its tenant became pending, a command it holds was
cancelled; `CommandRepository.SetChangeNotifier`), a re-check (30 s, which
also re-resolves the identity: a revoked key or sensor ends the stream with
UNAUTHENTICATED) or a keepalive (25 s). A wake always sends; a re-check
sends only a change. Streams close after 24–30 minutes and the sensor
reconnects; at most 4 per sensor.

Across replicas, the command and sensor notifiers are a `SensorWakeBus`: it
wakes this replica's hub at once and publishes `{origin, tenant, sensor}` on
Redis channel `sensor:v3:wake` from a bounded queue (a full queue drops the
wake; Wake never blocks a request). Every other replica delivers it to its
own hub. Redis is trusted with a hint only: a message that is malformed,
over 512 bytes or carries ids that are not UUIDs is dropped, and a wake only
ever makes a stream re-read the database. Without Redis, other replicas see
a change at their 30 s re-check.

## Transport per sensor

Every heartbeat stores, with the protocol telemetry, the binding it arrived on
(`sensors.protocol_binding`: `grpc`, `https` or `v2`) and the sensor's
fallback reason (`protocol_fallback_reason`, printable ASCII, 256
characters). The binding is the platform's: the v3 server marks the in-process
heartbeat with the listener it came on (`handler.WithServedTransport`); a
claimed binding in the body is ignored. A v3 heartbeat records protocol 3.
The sensors API returns them under `protocol.binding` /
`protocol.fallback_reason`; the detail sheet shows "Transport: …".

## Certificates and the gRPC binding

- **CA**: `SENSOR_MTLS_CA_CERT_FILE` + `SENSOR_MTLS_CA_KEY_FILE`, or created once
  in `SENSOR_MTLS_CA_DIR` (`/app/data/sensor-ca/sensor-ca.pem`, 0600 in 0700).
  ECDSA P-256, 10 years, path length 0. Its fingerprint is logged at start.
  The key is not the job signer's (RFC-040): a certificate opens a channel,
  it never authorizes a job. Rotating the CA: replace the files and restart;
  sensors get certificates from the new CA on their next `IssueCertificate`
  over HTTPS (their old certificate fails the handshake, which is a
  transport failure, so they fall back to HTTPS and renew).
- **Issuance** (`IssueCertificate`, either binding): for a key-bound sensor
  that is not paused, a certificate for its *registered* Ed25519 key, CN =
  sensor id, URI SAN `spiffe://openctem/tenant/<tenant>/sensor/<sensor>`, EKU
  clientAuth, `SENSOR_MTLS_CERT_TTL` (7 days). Budget: 5, then one per 10
  minutes per sensor. Recorded on the sensor timeline (`certificate_issued`).
  The answer carries the CA bundle the sensor pins for the gRPC host.
- **Listener** (`SENSOR_MTLS_LISTEN_ADDR`, `:8443`, only with
  `SENSOR_PUBLIC_HOST`): TLS 1.3, client certificate required and verified
  against the sensor CA only, ALPN `h2` only (anything else fails the
  handshake), server certificate minted from the CA for the public host. At
  the handshake and on every request the certificate key is resolved through
  the key table (`SigningIdentity`, cached 5 s): an unknown or revoked key, a
  revoked or deleted sensor, or a SAN that does not match the key's row is
  refused. A disabled sensor is paused as on v2.
- **Revocation of live streams**: activating, disabling, revoking or deleting
  a sensor and revoking a key wake its streams (`SetStatusNotifier`); the
  identity is re-resolved and a stream of a revoked identity ends with
  UNAUTHENTICATED within the wake jitter (test: under 2 s).

## Deploying the gRPC binding (Compose)

The gRPC binding needs a host name of its own, routed by SNI on port 443:

```bash
# DNS: sensors.example.com -> the gateway (same address as the platform host)
SENSOR_PUBLIC_HOSTNAME=sensors.example.com \
  docker compose -f docker-compose.yml -f docker-compose.sensor-passthrough.yml up -d --build
```

- The override builds the gateway with the layer4 module (`deploy/gateway/Dockerfile`,
  caddy-l4 pinned) and sets `OPENCTEM_SENSOR_GATEWAY=passthrough`: a TLS
  connection whose SNI is `SENSOR_PUBLIC_HOSTNAME` is not terminated; its bytes
  go to `api:8443` behind a PROXY protocol v2 header. Every other host is
  served exactly as before.
- It turns protocol v3 on in the API (`SENSOR_TRANSPORT_V3_ENABLED`,
  `SENSOR_PUBLIC_HOST=<name>:443`, `SENSOR_MTLS_LISTEN_ADDR=:8443`) and trusts
  the PROXY header from the gateway's address only
  (`SENSOR_MTLS_TRUSTED_PROXIES`); a PROXY header from any other peer closes
  the connection, so a sensor cannot choose the address it is recorded with.
- No public certificate is needed for the sensor host: the API mints its
  server certificate from the sensor CA and sensors pin that CA.
- The gateway entrypoint refuses `passthrough` without `SENSOR_PUBLIC_HOSTNAME`,
  with a port in it, with the platform host name, in TLS mode `http`, or on an
  image without the layer4 module.
- A separate port instead of SNI: publish the API's 8443 directly (or through
  any TCP load balancer) and set `SENSOR_PUBLIC_HOST=<host>:<port>`.

Without the override, `SENSOR_TRANSPORT_V3_ENABLED=true` alone serves the
HTTPS binding (`/api/v3/sensor`, through the normal TLS termination) and no
gRPC listener.

## Working on the proto

```bash
cd api
make proto          # regenerate api/pkg/sensorproto/v3 with the pinned buf and plugins
make proto-check    # what CI runs: lint, breaking against origin/develop, drift
```

Rules:

- Additive changes only (new fields, messages, RPCs, enum values). `buf
  breaking` (FILE rules) refuses anything else; a breaking change is a new
  package, `openctem.sensor.v4`.
- No field may name a tenant. The tenant and the sensor come from the
  authenticated identity.
- A document whose schema another specification owns (heartbeat, commands,
  CTIS, manifest, config report, suppressions) stays JSON bytes in its field;
  only the envelope is typed.
- Every RPC maps to one protocol v2 resource and is served through the v2
  handler chain, so the two protocols cannot disagree.

## RPC ↔ v2 resource

| RPC | v2 resource |
|---|---|
| `Hello` | `GET /api/v2/sensor/hello` |
| `Heartbeat` | `POST /heartbeat` |
| `Subscribe` | (new) the doorbell of the heartbeat answer, pushed |
| `ClaimCommands` | `GET /commands?limit=` (claim-N) |
| `TransitionCommand` | `POST /commands/{id}/claim\|start\|complete\|fail\|release` (+ `X-OpenCTEM-Lease-Epoch`) |
| `AppendCommandLogs` | `POST /commands/{id}/logs` |
| `PutResult` | `PUT /results/{report}` or `/results/{report}/segments/{n}` (and the command-bound forms) |
| `CommitResult` | `POST /results/{report}/commit` |
| `GetResultStatus` | `GET /results/{report}` |
| `AbandonResult` | `DELETE /results/{report}` |
| `PutManifest`, `GetManifest` | `PUT`, `GET /manifest` |
| `PutConfigReport` | `PUT /config-report` |
| `GetSuppressions` | `GET /suppressions` (+ `If-None-Match`) |
| `CheckFingerprints`, `BaselineDiff` | `POST /fingerprints/check`, `/fingerprints/baseline-diff` |
| `IssueCertificate` | (new) client certificate for the sensor's key |

`ClaimCommands` and the claim of `TransitionCommand` go through the same
claim-time scope re-check as v2: a scan job whose targets were refused after
it was queued comes back narrowed, or not at all (failed with
`SCOPE_CHANGED`; a claim by id answers `command-claimed`). See
[active-probe-gate.md](active-probe-gate.md#re-check-at-claim).
