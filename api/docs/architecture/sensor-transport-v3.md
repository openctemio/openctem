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
| Sensor CA, certificates, mTLS listener | planned | step 3 |
| Redis wake fan-out | planned | step 4 |
| Gateway SNI passthrough | planned | step 5 |

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
