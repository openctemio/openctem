# Sensor transport v3

Design: [RFC-059](../rfcs/RFC-059-sensor-transport-v3.md). This page says what
is built, where it lives and how to work on it.

## What is built

| Part | State | Where |
|---|---|---|
| Proto `openctem.sensor.v3.SensorService` | built | `api/proto/openctem/sensor/v3/sensor.proto` |
| Generated Go (protobuf + Connect) | built, committed | `api/pkg/sensorproto/v3`, `api/pkg/sensorproto/v3/sensorv3connect` |
| CI: buf lint, buf breaking, generated code current | built | `api/scripts/check-proto.sh`, step "Sensor Protocol v3" of API CI |
| HTTPS binding (`/api/v3/sensor`) | planned | RFC-059 §10 step 2 |
| Sensor CA, certificates, mTLS listener | planned | step 3 |
| Redis wake fan-out | planned | step 4 |
| Gateway SNI passthrough | planned | step 5 |

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
