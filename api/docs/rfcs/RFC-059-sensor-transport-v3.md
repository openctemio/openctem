# RFC-059: Sensor transport v3 — gRPC with mTLS, Connect/HTTPS fallback

| | |
|---|---|
| Status | Accepted (owner 2026-10-08: "implement the gRPC support plan"; decisions T1–T14 delegated) |
| Authors | Platform team |
| Related | RFC-026 (v2 results), RFC-029 (v2 control plane), RFC-030 (leases), RFC-032 (enrollment, identity), RFC-035 (doorbell), RFC-040 (mutual distrust), RFC-052 (pairing, key-bound sensors), RFC-055 (tool contract) |
| Code | `api/proto/openctem/sensor/v3/sensor.proto`, `api/pkg/sensorproto/v3` (generated), `api/internal/infra/sensortransport` (server), sdk-go `pkg/client` (client) |

## 1. Summary

Sensors reach the platform today with protocol v2: JSON resources over HTTPS,
every request signed with the sensor's Ed25519 key (RFC 9421), and polling: a
heartbeat every few seconds to 5 minutes says whether work is waiting, then
the sensor claims it.

Protocol v3 keeps that resource model and adds a second, stronger binding:

- **gRPC over HTTP/2 with mutual TLS** on a dedicated sensor host name. The
  client certificate is issued by a **sensor CA** for the sensor's registered
  key, lives 7 days and is renewed by the sensor; the tenant and sensor of
  every call come from it.
- **Connect over HTTPS** on the platform host (`/api/v3/sensor`), signed with
  RFC 9421 like v2, for networks where HTTP/2 or client certificates do not
  get through.
- A **control stream** (`Subscribe`): the platform pushes "work is waiting",
  cancels, pause and the other doorbell actions the moment they change, so a
  job reaches an idle sensor in under a second instead of at its next
  heartbeat. The database lease stays the only source of truth.

Both bindings are served by the same handlers, which run every call through
the v2 handler chain. v2 stays fully supported; v3 is off until
`SENSOR_TRANSPORT_V3_ENABLED=true`.

## 2. Motivation

- **Latency and load.** Polling trades latency against load: a 30-second idle
  heartbeat means up to 30 seconds before a job starts; a shorter interval
  multiplies requests across the fleet. A pushed doorbell removes the trade.
- **Channel identity.** A request signature authenticates each request. A
  client certificate also authenticates the connection, so a sensor that is
  revoked, deleted or whose key is revoked is refused at the handshake, and a
  long-lived stream is cut within seconds.
- **A typed, versioned contract.** A protobuf service with `buf lint` and
  `buf breaking` in CI gives implementers in any language a contract that
  cannot drift silently.

RFC-032 §5.2 chose request signatures over mTLS as the *default* because
TLS-inspecting egress proxies and TLS-terminating gateways break client
certificates. That reasoning still holds for those networks, which is why the
signed HTTPS binding stays and why the sensor falls back to it (§7); v3 makes
mTLS the preferred path where the network allows it.

## 3. Decisions

| # | Decision |
|---|---|
| T1 | One proto, package `openctem.sensor.v3`, service `SensorService`, in `api/proto` (a buf module). Generated Go is committed in `api/pkg/sensorproto/v3`. CI: `buf lint` (STANDARD), `buf breaking` against the base branch (FILE), generated code current (`scripts/check-proto.sh`). A breaking change needs a new package. |
| T2 | v3 binds the v2 resource model to RPCs: one RPC per v2 resource. The envelope is typed (ids, segment numbers, lease epochs, encodings, digests, entity tags, transport); documents whose schema another specification owns (heartbeat, commands, CTIS reports, manifest, config report, suppressions) travel as their JSON bytes, unchanged. The server serves each RPC by running it through the v2 handler chain in-process, so validation, limits, services and side effects are the same code, and one conformance suite covers both protocols. |
| T3 | The control channel is a server stream (`Subscribe`) plus unary calls, on both bindings. A bidirectional stream does not work over HTTP/1.1, which the fallback must support; with server streaming both bindings have the same semantics. The stream carries the doorbell, never a job; jobs are claimed with `ClaimCommands`. |
| T4 | Uploads are unary and resumable: `PutResult` sends a whole report or one segment, idempotent by report id + segment + Content-Digest (RFC-026); `GetResultStatus` tells what is missing after a disconnect. Logs are batched unary calls. Client streaming would not work over HTTP/1.1 and would add nothing to the exactly-once guarantee the segments already give. |
| T5 | Two bindings, one handler: gRPC on the mTLS listener (`SENSOR_MTLS_LISTEN_ADDR`, default `:8443`, paths at the root); Connect (and gRPC, gRPC-Web) under `/api/v3/sensor/` on the API's normal listener, behind the RFC 9421 authenticator. Both are mounted only with `SENSOR_TRANSPORT_V3_ENABLED=true`. |
| T6 | v3 requires a key-bound sensor (RFC-052). A bearer key is refused on v3; such sensors stay on v2 until they pair. |
| T7 | The client certificate certifies the sensor's registered Ed25519 key. `IssueCertificate` takes no CSR: the caller proved possession by signing the request (HTTPS) or in the handshake (gRPC). Subject CN = sensor id, URI SAN `spiffe://openctem/tenant/<tenant id>/sensor/<sensor id>`, extended key usage clientAuth, lifetime `SENSOR_MTLS_CERT_TTL` (default 7 days, 1 hour to 30 days). The sensor renews at two thirds of the lifetime. Issuance is rate-limited per sensor and recorded on the sensor's timeline. |
| T8 | Revocation needs no CRL: every handshake and every call resolves the certificate's key through the sensor's active keys and status (the same lookup as a signed v2 request) and checks that tenant and sensor in the certificate match the key's row. Results are cached at most 5 seconds. Streams re-check every 30 seconds and at once when the sensor's status changes. |
| T9 | The sensor CA is ECDSA P-256 with its own key, separate from the job signer (RFC-040): a certificate authenticates a channel and never authorizes a job. Loaded from `SENSOR_MTLS_CA_CERT_FILE` + `SENSOR_MTLS_CA_KEY_FILE`; when both are unset it is created once in `SENSOR_MTLS_CA_DIR` (default `data/sensor-ca`, i.e. `/app/data/sensor-ca` in the image; one file, mode 0600 in a 0700 directory, published with an atomic link so replicas sharing the volume agree). The mTLS listener's server certificate is minted in memory from the same CA for `SENSOR_PUBLIC_HOST`. |
| T10 | mTLS listener: TLS 1.3 only; client certificates required and verified against the sensor CA only; ALPN `h2` only; 16 MiB per message; the v2 per-sensor rate limits; a keepalive every 25 seconds on the stream; client deadlines honoured; no server reflection. |
| T11 | No message names a tenant. The tenant and the sensor are those of the authenticated identity; a command or report id of another sensor or tenant answers NOT_FOUND. A tenant-less (platform) sensor is refused on v3 as on v2. |
| T12 | Push fan-out: a hook in the command repository (a command becomes pending, a held one is cancelled, bulk re-queues) and the sensor status changes publish a wake (`{tenant_id, sensor_id?}`) on Redis channel `sensor:v3:wake`; every replica re-evaluates the doorbell for its streams of that tenant (jittered up to 250 ms). Without Redis each replica wakes its own streams and re-evaluates every 30 seconds. |
| T13 | Fallback in the SDK: `SENSOR_TRANSPORT=auto|grpc|https|v2`. `auto` tries gRPC, then on a transport-level failure (dial or handshake failure, no HTTP/2, a stream reset by an intermediary, Unimplemented) the HTTPS binding, then v2 when the platform has no v3. It never falls back on an identity error (UNAUTHENTICATED, PERMISSION_DENIED from the platform). gRPC is probed again every 30 minutes. The heartbeat reports the binding and the fallback reason; the platform stores the binding it served and shows both per sensor. |
| T14 | Same port 443 by SNI: the gateway passes TLS for `SENSOR_PUBLIC_HOST` through at layer 4 to the API's mTLS listener (with PROXY protocol v2, accepted only from `SENSOR_MTLS_TRUSTED_PROXIES`) and terminates every other host as today. A separate port is a configuration option. |

## 4. The service

```
service SensorService {
  Hello · Heartbeat · Subscribe (server stream)
  ClaimCommands · TransitionCommand (claim | start | complete | fail | release) · AppendCommandLogs
  PutResult · CommitResult · GetResultStatus · AbandonResult
  PutManifest · GetManifest · PutConfigReport · GetSuppressions · CheckFingerprints · BaselineDiff
  IssueCertificate
}
```

Every RPC maps to one v2 resource (`/api/v2/sensor/...`). The proto file is
the reference; each message documents its fields. Errors are Connect/gRPC
codes mapped from the v2 HTTP status (400 → INVALID_ARGUMENT, 401 →
UNAUTHENTICATED, 403 → PERMISSION_DENIED, 404 → NOT_FOUND, 409 → ABORTED,
413 → RESOURCE_EXHAUSTED, 415/422 → INVALID_ARGUMENT, 429 →
RESOURCE_EXHAUSTED, 503 → UNAVAILABLE, 500 → INTERNAL), with an
`openctem.sensor.v3.Problem` detail carrying the RFC 9457 document v2 would
have returned.

`Hello` returns the v2 hello document (features, limits) plus the gRPC
endpoint. The v2 hello lists `transport_v3` with the HTTPS path and the gRPC
endpoint when v3 is on, so a v2 sensor discovers v3 without a new request.

## 5. Identity and certificates

```
sensor (key-bound, Ed25519 key from pairing)
  │ 1. IssueCertificate over HTTPS (/api/v3/sensor), RFC 9421-signed
  ▼
platform: SigningIdentity(keyid) → sensor + tenant, status
  │ 2. certificate for the registered key, CA bundle to pin, gRPC endpoint
  ▼
sensor ──TLS 1.3, client cert──► sensors.<domain>:443 ──SNI passthrough──► api:8443
                                   (gateway does not terminate)            VerifyConnection:
                                                                          chain → sensor CA,
                                                                          key → active key row,
                                                                          SAN ids = row ids,
                                                                          sensor not revoked
```

The sensor verifies the platform's server certificate on the gRPC host
against the CA bundle from step 2 only (no system roots), so a TLS-inspecting
proxy cannot impersonate the platform there. The HTTPS binding keeps the
normal verification (system roots or the operator's `SENSOR_CA_CERT_FILE`).

## 6. Control stream and push

`Subscribe` sends the doorbell when it changes and a keepalive every 25
seconds. The doorbell is computed by the same code as the heartbeat answer
(pending jobs, actions, cancel ids, config version). What wakes a stream:
a command created, updated (cancelled, re-queued, released) or cancelled with
its scan run in the stream's tenant; a status change of the sensor (pause,
revoke). The sensor reacts exactly as to a heartbeat answer: it claims with
`ClaimCommands`, which applies every dispatch gate (grants, scope, tier,
zones, capacity) as v2 does. A lost wake or a dropped stream costs latency,
never a job: the heartbeat still carries the doorbell.

## 7. Fallback

| Situation | Sensor does | Reported reason |
|---|---|---|
| gRPC host unreachable, handshake fails, ALPN without h2, stream reset by a proxy, UNIMPLEMENTED | HTTPS binding; retries gRPC every 30 min | `grpc_unreachable`, `handshake_failed`, `http2_refused`, `stream_reset`, `grpc_unimplemented` |
| Platform has no v3 (no `transport_v3` in hello) | v2 | `platform_without_v3` |
| `SENSOR_TRANSPORT=https` or `v2` | as configured | `forced_by_config` |
| UNAUTHENTICATED / PERMISSION_DENIED, certificate refused by the platform, sensor revoked | stops and reports the error; no fallback | — |

## 8. Security

Threat model (each row has a test):

| Attacker | Attempt | Control |
|---|---|---|
| Sensor of tenant A | use tenant B's command or report ids | ids looked up scoped to the authenticated tenant and sensor; NOT_FOUND |
| Holder of an expired, revoked or foreign-CA certificate | connect | TLS chain and expiry; key and sensor status at the handshake and on every call (T8); only the sensor CA is trusted |
| Holder of a valid certificate whose key or sensor was revoked | keep a stream open | re-check every 30 s and on the status-change wake |
| Network attacker | force a downgrade | no fallback on identity errors; the HTTPS binding keeps full TLS verification and request signatures; the binding and reason are visible per sensor; a tenant policy "require mTLS" can refuse the fallback (planned) |
| Network attacker | impersonate the platform on the gRPC host | the sensor pins the sensor CA there |
| Replay of an upload | double ingest | report id + segment + digest idempotency |
| Hostile sensor | oversized or malformed input, flooding | 16 MiB message cap, the v2 edge chain (content type, encoding, digest, decompression bounds, JSON depth), per-sensor rate limits |
| Compromised API host | abuse the CA | the CA key is not the job-signing key (RFC-040); certificates are short-lived and bound to registered keys |
| Tenant | see platform sensors | tenant-less sensors are refused on v3 as on v2; the platform-sensor masking of #1362 is unchanged |

Tenant isolation: no proto field carries a tenant; the identity comes from
the certificate or the signature; every lookup is tenant- and sensor-scoped
by the v2 code it reuses.

## 9. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SENSOR_TRANSPORT_V3_ENABLED` | `false` | Mount v3 (both bindings) |
| `SENSOR_PUBLIC_HOST` | — | Host name sensors use for gRPC (e.g. `sensors.example.com[:443]`); no gRPC binding without it |
| `SENSOR_MTLS_LISTEN_ADDR` | `:8443` | mTLS listener |
| `SENSOR_MTLS_CA_CERT_FILE` / `SENSOR_MTLS_CA_KEY_FILE` | — | Sensor CA (PEM) |
| `SENSOR_MTLS_CA_DIR` | `data/sensor-ca` (in the image: `/app/data/sensor-ca`, on the `api-data` volume) | Where the CA is created when the files are unset |
| `SENSOR_MTLS_CERT_TTL` | `168h` | Client certificate lifetime (1h–720h) |
| `SENSOR_MTLS_TRUSTED_PROXIES` | — | CIDRs whose PROXY protocol header is believed on the mTLS listener |

## 10. Rollout

| Step | Repository | Content |
|---|---|---|
| 1 | openctem | this RFC, the proto, buf CI, generated code |
| 2 | openctem | HTTPS binding behind the flag: every RPC through the v2 chain, `Subscribe`, transport per sensor |
| 3 | openctem | sensor CA, `IssueCertificate`, mTLS listener, revocation |
| 4 | openctem | Redis wake fan-out |
| 5 | openctem | gateway SNI passthrough (compose), PROXY protocol; web shows the transport |
| 6 | sdk-go | v3 client (both bindings), certificate manager, control stream, fallback |
| 7 | sensor | adopt; `SENSOR_TRANSPORT`; end-to-end on a scratch stack |
| 8 | helm-charts, docs | passthrough values, sensor host, upgrade notes |

Upgrade: nothing changes until the flag is set. Turning it on needs a DNS
name for `SENSOR_PUBLIC_HOST` pointing at the gateway; sensors pick v3 up on
their next hello. Turning it off sends every sensor back to v2 at its next
call.

## 11. Alternatives considered

- **Bidirectional stream on gRPC only.** Rejected: the HTTPS fallback would
  need a different shape and a second conformance suite.
- **Re-model every document in protobuf.** Rejected for now: the heartbeat,
  manifest, CTIS and config report already have owners and versioning; a
  second definition would drift. They can become typed messages later
  without a new package (new fields).
- **Terminate mTLS at the gateway and forward the certificate in a header.**
  Rejected: the API would trust a header for identity, and every hop between
  would have to be trusted with it.
- **A certificate revocation list.** Rejected: the key table already decides,
  per call; a list would be a second source of truth.
