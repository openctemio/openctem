# RFC-059: Sensor transport v3 — gRPC with mTLS, Connect/HTTPS fallback

| | |
|---|---|
| Status | Accepted (owner 2026-10-08: "implement the gRPC support plan"; decisions T1–T14 delegated; revised by the owner 2026-10-11: no enable flag, bindings chosen automatically, T15; one port for every setup by ALPN routing, T16; the same without a gateway, T17) |
| Authors | Platform team |
| Related | RFC-026 (v2 results), RFC-029 (v2 control plane), RFC-030 (leases), RFC-032 (enrollment, identity), RFC-035 (doorbell), RFC-040 (mutual distrust), RFC-052 (pairing, key-bound sensors), RFC-055 (tool contract) |
| Code | `api/proto/openctem/sensor/v3/sensor.proto`, `api/pkg/sensorproto/v3` (generated), `api/internal/infra/sensortransport` (server), sdk-go `pkg/client` (client) |

## 1. Summary

Sensors reach the platform today with protocol v2: JSON resources over HTTPS,
every request signed with the sensor's Ed25519 key (RFC 9421), and polling: a
heartbeat every few seconds to 5 minutes says whether work is waiting, then
the sensor claims it.

Protocol v3 keeps that resource model and adds a second, stronger binding:

- **gRPC over HTTP/2 with mutual TLS** on the platform's own port 443,
  routed by the gateway on a sensor ALPN id (T16), or on a dedicated sensor
  host name or a port of its own. The
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
the v2 handler chain. v2 stays fully supported. No operator switch turns a
binding on: the HTTPS binding is always served, and the gRPC binding is
advertised only while the platform's own probe reaches it (T15);
`SENSOR_TRANSPORT_V3=off` is the emergency switch back to v2.

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
| T5 | Two bindings, one handler: gRPC on the mTLS listener (`SENSOR_MTLS_LISTEN_ADDR`, default `:9443`, paths at the root); Connect (and gRPC, gRPC-Web) under `/api/v3/sensor/` on the API's normal listener, behind the RFC 9421 authenticator. Both are mounted unless `SENSOR_TRANSPORT_V3=off`. |
| T6 | v3 requires a key-bound sensor (RFC-052). A bearer key is refused on v3; such sensors stay on v2 until they pair. |
| T7 | The client certificate certifies the sensor's registered Ed25519 key. `IssueCertificate` takes no CSR: the caller proved possession by signing the request (HTTPS) or in the handshake (gRPC). Subject CN = sensor id, URI SAN `spiffe://openctem/tenant/<tenant id>/sensor/<sensor id>`, extended key usage clientAuth, lifetime `SENSOR_MTLS_CERT_TTL` (default 7 days, 1 hour to 30 days). The sensor renews at two thirds of the lifetime. Issuance is rate-limited per sensor and recorded on the sensor's timeline. |
| T8 | Revocation needs no CRL: every handshake and every call resolves the certificate's key through the sensor's active keys and status (the same lookup as a signed v2 request) and checks that tenant and sensor in the certificate match the key's row. Results are cached at most 5 seconds. Streams re-check every 30 seconds and at once when the sensor's status changes. |
| T9 | The sensor CA is ECDSA P-256 with its own key, separate from the job signer (RFC-040): a certificate authenticates a channel and never authorizes a job. Loaded from `SENSOR_MTLS_CA_CERT_FILE` + `SENSOR_MTLS_CA_KEY_FILE`; when both are unset it is created once in `SENSOR_MTLS_CA_DIR` (default `data/sensor-ca`, i.e. `/app/data/sensor-ca` in the image; one file, mode 0600 in a 0700 directory, published with an atomic link so replicas sharing the volume agree). The mTLS listener's server certificate is minted in memory from the same CA for `SENSOR_PUBLIC_HOST`. |
| T10 | mTLS listener: TLS 1.3 only; client certificates required and verified against the sensor CA only; ALPN `h2` only; 16 MiB per message; the v2 per-sensor rate limits; a keepalive every 25 seconds on the stream; client deadlines honoured; no server reflection. |
| T11 | No message names a tenant. The tenant and the sensor are those of the authenticated identity; a command or report id of another sensor or tenant answers NOT_FOUND. A tenant-less (platform) sensor is refused on v3 as on v2. |
| T12 | Push fan-out: a hook in the command repository (a command becomes pending, a held one is cancelled, bulk re-queues) and the sensor status changes publish a wake (`{tenant_id, sensor_id?}`) on Redis channel `sensor:v3:wake`; every replica re-evaluates the doorbell for its streams of that tenant (jittered up to 250 ms). Without Redis each replica wakes its own streams and re-evaluates every 30 seconds. |
| T13 | Fallback in the SDK: `SENSOR_TRANSPORT=auto|grpc|https|v2`. `auto` tries gRPC, then on a transport-level failure (dial or handshake failure, no HTTP/2, a stream reset by an intermediary, Unimplemented) the HTTPS binding, then v2 when the platform has no v3. It never falls back on an identity error (UNAUTHENTICATED, PERMISSION_DENIED from the platform): it then sends only hello and the heartbeat until the identity is accepted. After a network failure gRPC is tried again after 30 minutes, doubling per consecutive failure up to 4 hours, remembered across restarts in the certificate directory; a platform that offers no gRPC (or no v3) yet is asked again within 10 minutes. The heartbeat reports the binding and the fallback reason; the platform stores the binding it served and shows both per sensor. |
| T15 | Automatic selection (owner revision 2026-10-11). The HTTPS binding is always served. The gRPC listener starts once the sensor CA loads and a public host is known (`SENSOR_PUBLIC_HOST`, else the host and port of the platform URL, T16). A self-probe dials that host every minute (30 s while failing), TLS 1.3 offering the ALPN ids `h2` and `openctem-sensor/3`, verifying the server certificate against the sensor CA only; hello names the gRPC endpoint only while the probe passes. The state and reason are shown to platform admins (Console > Operations, `GET /api/v1/admin/operations` field `sensor_transport`), in metrics and in a log line per change; organization users never see installation infrastructure. `SENSOR_TRANSPORT_V3=auto|off` replaces the enable flag; `off` sends every sensor back to v2. |
| T14 | Same port 443 by SNI, kept as an option next to T16: the gateway passes TLS for a dedicated sensor host name (`SENSOR_PUBLIC_HOSTNAME`) through at layer 4 to the API's mTLS listener (with PROXY protocol v2, accepted only from `SENSOR_MTLS_TRUSTED_PROXIES`) and terminates every other host as today. A separate port is a configuration option (`SENSOR_PUBLIC_HOST` with its own port, published by the operator). |
| T16 | Same port 443 for every setup by ALPN (owner revision 2026-10-11: no extra port in any deployment). SNI cannot route an IP address (clients send no server name for one) nor share one host name with the web UI. The sensor's gRPC client therefore offers a dedicated ALPN protocol id, `openctem-sensor/3`, next to `h2`; the gateway's layer-4 router (the gateway image with the layer4 module, `OPENCTEM_SENSOR_GATEWAY=alpn`) passes a ClientHello that offers it through, untouched and with PROXY protocol v2, to the API's mTLS listener, and terminates every other connection as before. The listener lists only `h2` and negotiates it (server preference), so the HTTP/2 stack on both ends is unchanged and no gRPC library has to accept a custom protocol. Without `SENSOR_PUBLIC_HOST` the endpoint is the platform URL's host and port (a name or an address). The self-probe offers the same ids; once it passes, a second probe offers `h2` only: when that passes too (a port of its own, a dedicated SNI host) hello names the endpoint as `grpc_endpoint`, otherwise only as `grpc_alpn_endpoint`, so clients that do not offer the id (which would meet the gateway's own certificate and stop with `platform_certificate_refused`) stay on the HTTPS binding. Behind the stock gateway the probe meets the gateway's certificate and nothing changes: HTTPS binding. |
| T17 | One port without a gateway (owner question 2026-10-11: web and API deployed separately, no extra port). When `SERVER_TLS_CERT_FILE` and `SERVER_TLS_KEY_FILE` are set the API listener terminates TLS itself and splits by ALPN in the handshake (`tls.Config.GetConfigForClient`): a ClientHello that offers `openctem-sensor/3` gets the mTLS listener's own config (sensor-CA server certificate, client certificate required and resolved at the handshake, `h2` only) and is served by the mTLS listener's server, which resolves the certificate again on every call; any other ClientHello gets the operator's certificate and the normal API (h2 and HTTP/1.1). Same code paths as the dedicated listener, so no weaker check; a PROXY protocol v2 header is believed only from `SENSOR_MTLS_TRUSTED_PROXIES` (it precedes the ClientHello, so the rule covers the whole port). The endpoint is the platform URL's host and port as in T16, advertised by the same two-step probe as `grpc_alpn_endpoint`. Without the two variables (the default) the API serves plain HTTP behind a TLS proxy, unchanged. |

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
sensor ──TLS 1.3, client cert, ALPN [h2, openctem-sensor/3]──► <platform host>:443
                                                                  │ gateway layer 4: the ClientHello
                                                                  │ offers openctem-sensor/3 (or names
                                                                  │ the dedicated sensor host, T14)
                                                                  ▼ passthrough + PROXY protocol v2
                                                               api:9443  negotiates h2;
                                                                         VerifyConnection:
                                                                         chain → sensor CA,
                                                                         key → active key row,
                                                                         SAN ids = row ids,
                                                                         sensor not revoked
browsers, API clients, HTTPS binding (no sensor id) ──► same :443 ──► gateway terminates TLS (planes)
```

The sensor verifies the platform's server certificate on the gRPC host
against the CA bundle from step 2 only (no system roots), so a TLS-inspecting
proxy cannot impersonate the platform there. The HTTPS binding keeps the
normal verification (system roots or the operator's `SENSOR_CA_CERT_FILE`).

The ALPN id routes; it does not authenticate. Anyone can offer it and reach
the mTLS listener, exactly as anyone could reach a published mTLS port: the
client certificate (chain to the sensor CA, a registered active key, matching
ids) is the only identity check, at the handshake and on every call.

### 5.1 Deployment modes

Every setup reaches the gRPC binding on the port clients already use, or
falls back to the HTTPS binding by itself. What decides it is whether some
component on the path can read the ClientHello and pass the sensor's
connection, still encrypted, to an mTLS listener of the API.

| Setup | What routes the sensor connection | Endpoint sensors get | Notes |
|---|---|---|---|
| Our gateway, IP address only, one port (e.g. `https://192.0.2.10`) | layer4 image, `OPENCTEM_SENSOR_GATEWAY=alpn` | `192.0.2.10:443` as `grpc_alpn_endpoint` | Server certificate minted with an IP SAN by the sensor CA; the API's probe must reach the address from inside its container (hairpin through the published port) |
| Our gateway, one host name for everything (e.g. `ctem.example.com`) | layer4 image, `alpn` | `ctem.example.com:443` as `grpc_alpn_endpoint` | No extra DNS name or certificate; the public certificate for the web UI is unaffected |
| Our gateway, dedicated sensor host name (e.g. `sensors.example.com`) | layer4 image, `passthrough` + `SENSOR_PUBLIC_HOSTNAME`; API `SENSOR_PUBLIC_HOST=sensors.example.com:443` | as `grpc_endpoint` and `grpc_alpn_endpoint` | Routed by SNI and by ALPN; also reached by sensors that do not offer the ALPN id yet |
| Our gateway, stock image (no layer4) | nothing | none: HTTPS binding | The probe meets the gateway's certificate (`foreign_certificate`); nothing to configure |
| No gateway: API exposed directly (web served elsewhere) | the API itself (T17): `SERVER_TLS_CERT_FILE`, `SERVER_TLS_KEY_FILE` | the API URL's host and port (`SENSOR_PUBLIC_API_URL`) as `grpc_alpn_endpoint` | One port for API clients and sensors; the certificate files are re-read when they change |
| No gateway: API behind an L4 (TCP) load balancer | the API itself (T17) behind the balancer | the balancer's host and port as `grpc_alpn_endpoint` | The balancer must pass TCP unchanged. If it sends PROXY protocol v2, list its addresses in `SENSOR_MTLS_TRUSTED_PROXIES` (then also believed for API clients on that port) |
| Own TLS proxy with ALPN-aware TCP routing (nginx `stream` + `ssl_preread`, HAProxy `mode tcp`) | the proxy: a ClientHello offering `openctem-sensor/3` goes to the API's `:9443` untouched, everything else to the HTTPS service | the proxy's host and port as `grpc_alpn_endpoint` | Example configs in the architecture doc, both tested against the mTLS listener |
| SNI-only passthrough (e.g. a Kubernetes ingress with ssl-passthrough) | the proxy, by a dedicated sensor host name, to the API's `:9443` | `SENSOR_PUBLIC_HOST=sensors.example.com:443` as both fields | A router that reads SNI only cannot route by ALPN; give sensors their own name |
| L7 load balancer or proxy that terminates TLS and cannot pass TCP through | nothing | none: HTTPS binding | Automatic. The `Subscribe` stream and every RPC work over the Connect protocol on HTTP/1.1 or HTTP/2; keep response buffering off |
| Separate port (explicit) | the operator publishes the API's `:9443` | `SENSOR_PUBLIC_HOST` (e.g. `192.0.2.10:9443`) as both fields | Only when configured; no PROXY protocol unless a proxy in front sends it |
| Kubernetes | see notes | — | Expose the gateway image (or the API with T17) through a `LoadBalancer` Service for ALPN routing, use a dedicated sensor host with ssl-passthrough, or stay on the HTTPS binding through any ingress. Chart support is a follow-up (helm-charts: gateway image with layer4, `OPENCTEM_SENSOR_GATEWAY`, `SENSOR_MTLS_TRUSTED_PROXIES` for the gateway pods) |

In every row the self-probe decides what hello names: it passes only when the
path reaches an mTLS listener of the API, so a wrong configuration costs
nothing but the move to the gRPC binding.

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

The platform side decides first what it offers: the gRPC endpoint is in
hello only while the self-probe (T15) reaches the mTLS listener through the
public host, offering the sensor ALPN id like a sensor. Only that listener
holds a certificate from the sensor CA, so a gateway that terminates TLS for
the name (the stock gateway, or no ALPN or SNI routing), a closed port, a
name that does not resolve or a path without HTTP/2 fail the probe, with the
reason `foreign_certificate`, `unreachable`, `dns_failed`, `handshake_failed`
or `http2_refused`; no public host gives `no_public_host`, no CA
`sensor_ca_unavailable`. Sensors are then offered the HTTPS binding only,
and no sensor is sent to an endpoint that cannot work. A passing probe is
followed by one without the sensor ALPN id: if it fails, the endpoint is
reachable only through ALPN routing (`requires_alpn` in
`sensor_transport` on Console > Operations, metric result `ok_alpn`) and hello names it
as `grpc_alpn_endpoint` only; clients that do not offer the id never see it.
The sensor side then falls back as follows when its own path differs from
the platform's:

| Situation | Sensor does | Reported reason |
|---|---|---|
| gRPC host unreachable, handshake fails, ALPN without h2, stream reset by a proxy, UNIMPLEMENTED | HTTPS binding; retries gRPC every 30 min | `grpc_unreachable`, `handshake_failed`, `http2_refused`, `stream_reset`, `grpc_unimplemented` |
| Platform has no v3 (no `transport_v3` in hello) | v2 | `platform_without_v3` |
| `SENSOR_TRANSPORT=https` or `v2` | as configured | `forced_by_config` |
| UNAUTHENTICATED / PERMISSION_DENIED, certificate refused by the platform, sensor revoked | stops and reports the error; no fallback | — |
| The gRPC endpoint presents a certificate that does not verify against the pinned sensor CA (a gateway that stopped routing the ALPN id, a TLS-inspecting proxy) | sends nothing until a later negotiation verifies it; no fallback | `platform_certificate_refused` |

## 8. Security

Threat model (each row has a test):

| Attacker | Attempt | Control |
|---|---|---|
| Sensor of tenant A | use tenant B's command or report ids | ids looked up scoped to the authenticated tenant and sensor; NOT_FOUND |
| Holder of an expired, revoked or foreign-CA certificate | connect | TLS chain and expiry; key and sensor status at the handshake and on every call (T8); only the sensor CA is trusted |
| Holder of a valid certificate whose key or sensor was revoked | keep a stream open | re-check every 30 s and on the status-change wake |
| Network attacker | force a downgrade | no fallback on identity errors; the HTTPS binding keeps full TLS verification and request signatures; the binding and reason are visible per sensor; a tenant policy "require mTLS" can refuse the fallback (planned) |
| Network attacker | impersonate the platform on the gRPC host | the sensor pins the sensor CA there |
| Anyone on the network | offer the sensor ALPN id to reach the mTLS listener through port 443 | the id only routes; the listener requires a sensor-CA client certificate whose key is an active registered key, as on a published port; refused handshakes are debug logs |
| Anyone on the network | offer the sensor ALPN id to the API's own TLS port (T17) | the split hands the connection the mTLS listener's TLS config and server: sensor-CA client certificate required and resolved at the handshake and on every call, `h2` only; without the gRPC binding the id gets the public certificate and the normal API |
| Client behind the gateway | forge its address with a PROXY protocol header | the listener believes PROXY headers only from `SENSOR_MTLS_TRUSTED_PROXIES` (the gateway's fixed address) and closes a connection that sends one from elsewhere |
| Gateway misconfiguration | ALPN routing removed after sensors pinned the endpoint | the probe fails within 30 s and hello withdraws the endpoint; sensors meet a foreign certificate (`platform_certificate_refused`, no downgrade) until their next negotiation moves them to the HTTPS binding |
| Older sensor (no ALPN id) | sent to a single-port endpoint it cannot reach | that endpoint is named only as `grpc_alpn_endpoint`, which older clients do not read |
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
| `SENSOR_TRANSPORT_V3` | `auto` | `auto`: HTTPS binding always, gRPC binding while its self-probe passes; `off`: no v3, every sensor on v2 (emergency switch). The former `SENSOR_TRANSPORT_V3_ENABLED` is refused at startup |
| `SENSOR_PUBLIC_HOST` | host and port (default 443) of the platform URL (`SENSOR_PUBLIC_API_URL`, else `APP_URL`, https only), a name or an address | Endpoint sensors dial for gRPC. Unset: the platform's own port through the gateway's ALPN routing. Set it for a dedicated sensor host (`sensors.example.com:443`) or a port of its own (`192.0.2.10:9443`) |
| `SENSOR_MTLS_LISTEN_ADDR` | `:9443` | mTLS listener |
| `SENSOR_MTLS_CA_CERT_FILE` / `SENSOR_MTLS_CA_KEY_FILE` | — | Sensor CA (PEM) |
| `SENSOR_MTLS_CA_DIR` | `data/sensor-ca` (in the API image: `/app/data/sensor-ca`, on the `api-data` volume; in the all-in-one image: `/data/sensor-ca`, on its `/data` volume) | Where the CA is created when the files are unset |
| `SENSOR_MTLS_CERT_TTL` | `168h` | Client certificate lifetime (1h–720h) |
| `SERVER_TLS_CERT_FILE` / `SERVER_TLS_KEY_FILE` | — (plain HTTP) | PEM paths: the API listener terminates TLS itself and serves the gRPC binding on the same port to ClientHellos offering `openctem-sensor/3` (T17). Set both or neither |
| `SENSOR_MTLS_TRUSTED_PROXIES` | — | CIDRs whose PROXY protocol header is believed on the mTLS listener (the gateway's fixed address); required behind the layer4 gateway, which always sends one |

Gateway (`deploy/gateway`, the image built from its `Dockerfile` with the
layer4 module; `deploy/docker-compose.sensor-passthrough.yml`):

| Variable | Default | Meaning |
|---|---|---|
| `OPENCTEM_SENSOR_GATEWAY` | `off` (`alpn` in the override file) | `off`: no layer-4 routing; `alpn`: a ClientHello offering `openctem-sensor/3` goes to the mTLS listener; `passthrough`: that, and TLS for `SENSOR_PUBLIC_HOSTNAME` by SNI. `alpn` and `passthrough` need the layer4 image and a TLS mode; the entrypoint refuses them otherwise |
| `SENSOR_PUBLIC_HOSTNAME` | — | Dedicated sensor host name for `passthrough` (no port; must differ from `OPENCTEM_HOSTNAME`) |
| `SENSOR_MTLS_UPSTREAM` | `api:9443` | The API's mTLS listener |

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
| 9 | openctem, sdk-go, sensor | ALPN routing on the platform's own port (T16): gateway `alpn` mode, endpoint derived from the platform URL, two-step probe, `grpc_alpn_endpoint`; the client offers `openctem-sensor/3` |
| 10 | helm-charts | follow-up: the gateway image with layer4 and `OPENCTEM_SENSOR_GATEWAY` in the chart, the gateway's address in `SENSOR_MTLS_TRUSTED_PROXIES` |
| 11 | openctem | one port without a gateway (T17): the API terminates TLS itself and splits by ALPN |

Upgrade: key-bound sensors move to the HTTPS binding at their next hello
with no configuration. The gRPC binding needs a path to the mTLS listener:
the gateway image with layer4 in `alpn` mode on the platform's own port
(T16, nothing else to configure: the API derives the endpoint from its
URL), a DNS name routed by SNI (`passthrough`, T14), or a port of its own;
once the self-probe passes, sensors that offer the ALPN id (sdk-go with
`client.SensorALPN`) move to it at their next hello, older ones keep the
HTTPS binding unless the endpoint is also reachable without the id. Switching
the gateway image restarts it (a few seconds without UI or API).
`SENSOR_TRANSPORT_V3=off` sends every sensor back to v2 at its next call.

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
