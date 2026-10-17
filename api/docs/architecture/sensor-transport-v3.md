# Sensor transport v3

Design: [RFC-059](../rfcs/RFC-059-sensor-transport-v3.md). This page says what
is built, where it lives and how to work on it.

## What is built

| Part | State | Where |
|---|---|---|
| Proto `openctem.sensor.v3.SensorService` | built | `api/proto/openctem/sensor/v3/sensor.proto` |
| Generated Go (protobuf + Connect) | built, committed | `api/pkg/sensorproto/v3`, `api/pkg/sensorproto/v3/sensorv3connect` |
| CI: buf lint, buf breaking, generated code current | built | `api/scripts/check-proto.sh`, step "Sensor Protocol v3" of API CI |
| HTTPS binding (`/api/v3/sensor`) | built, served unless `SENSOR_TRANSPORT_V3=off` | `internal/infra/sensortransport` (server), `handler/sensor_v3_bridge.go` (identity, in-process authenticator, stream hints), `routes/sensor_v2.go` (`sensorV2InProcess`) |
| Control stream `Subscribe`, push on command changes (one replica) | built | `sensortransport/subscribe.go`, `postgres/command_notify.go` |
| Sensor CA, `IssueCertificate`, mTLS listener (gRPC binding), revocation | built | `sensortransport/ca.go`, `issuer.go`, `mtls.go`; `SensorService.SetStatusNotifier` |
| Redis wake fan-out across replicas | built | `internal/infra/redis/sensor_wake.go` (`SensorWakeBus`, channel `sensor:v3:wake`) |
| gRPC self-probe: endpoint advertised only while reachable; Console > Operations, metrics | built | `sensortransport/probe.go`, `handler/sensor_transport_status_handler.go`, `cmd/server/handlers.go` (`setupSensorGRPC`) |
| Gateway SNI passthrough (Compose), PROXY protocol | built | `deploy/gateway/Dockerfile`, `deploy/gateway/sensors/*.wrappers`, `deploy/docker-compose.sensor-passthrough.yml`; `SENSOR_MTLS_TRUSTED_PROXIES` |
| One port without a gateway: the API terminates TLS and splits by ALPN (`SERVER_TLS_CERT_FILE`) | built | `sensortransport/native.go` (`SplitTLS`), `internal/infra/http/tls.go` |

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

Guards ahead of authentication: the binding is reachable without
credentials, and verifying a signature costs a database lookup of the key, so
before any of that runs:

- the global per-IP rate limit applies (`MountPrefix` wraps the binding with
  it, although the rest of the global middleware is skipped);
- at most `MaxUnaryInFlight` (256) unary calls per replica are in flight
  across both bindings; over it a call gets `503` with `Retry-After` before a
  byte is read. Control streams take no slot (they are bounded per sensor);
- a control stream's read and write deadlines are lifted only after it
  authenticated; on the gRPC binding a unary call must deliver its message
  within `UnaryTimeout` (the listener has no read timeout because of the
  streams).

The key-use bookkeeping of an authenticated call (sensor last seen, last IP,
key last used) is written at most once per 15 seconds per sensor and
address.

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

### Wake and stream-open limits

A tenant-wide wake (a command released, refused or returned to the pool)
makes every stream of the tenant on every replica re-authenticate and re-read
the doorbell, and v3 streams are cheap to open. So a tenant or a sensor
cannot drive that work at its own pace (research/84 RE-12):

| Limit | Value | Where | Over it |
|---|---|---|---|
| Wake coalescing | one delivery per 500 ms (`WakeCoalesce`) per tenant, per sensor, and for wake-all | each replica's hub (`Hub.Wake`), and the bus's publishes | the wakes inside the interval fold into **one** delivered when it ends: delayed, never lost (the 30 s re-check stays the backstop). A wake for a tenant with no stream on the replica costs nothing |
| Publish quota | 32 queued wakes per tenant (wake-all counts as one tenant) of the 1024-wake publish queue | `SensorWakeBus.enqueue` | the excess folds into one tenant-wide wake, queued as soon as one of the tenant's queued wakes is published; another tenant's wake still finds room. Counted in `openctem_sensor_wakes_coalesced_total{reason="tenant_quota"}` (`queue_full` when the whole queue is full: dropped, re-check backstop) |
| Stream opens | token bucket per sensor per replica: 6 per minute, burst 10 (`StreamOpensPerMinute`, `StreamOpenBurst`) | first thing in `Subscribe`, after the identity, before the hub and any database read | `ResourceExhausted`; counted in `openctem_sensor_stream_opens_refused_total{reason="rate"}` (`concurrent` for the 4-stream bound) |

The burst covers a sensor's normal reconnects (the 24–30 minute stream age,
a replica shutdown, a network blip); the coalescing interval is below the
wake jitter's order of magnitude, so a single change is still pushed at
once. `pkg/coalesce` holds the per-key trailing-edge throttle both use; idle
keys are swept, so memory follows the active tenants and sensors.

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
- **Listener** (`SENSOR_MTLS_LISTEN_ADDR`, `:9443`, only with
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

The gRPC binding shares port 443 with the web UI and the API in every setup
(an IP address, one host name, no DNS at all; RFC-059 T16):

```bash
docker compose -f docker-compose.yml -f docker-compose.sensor-passthrough.yml up -d
```

- The stack's gateway image (`ghcr.io/openctemio/openctem-gateway`, built from
  `deploy/gateway/Dockerfile` with caddy-l4 pinned) has the layer4 module; the
  override sets `OPENCTEM_SENSOR_GATEWAY=alpn`
  (`sensors/alpn.wrappers`): a TLS connection whose ClientHello offers the ALPN
  id `openctem-sensor/3` is not terminated; its bytes go to `api:9443` behind a
  PROXY protocol v2 header. Every other connection (browsers on h2 or
  HTTP/1.1, WebSockets, API clients, sensors on the HTTPS binding or v2) is
  served exactly as before: none of them offers that id.
- The API derives the endpoint from its own URL (`APP_URL` host and port) and
  advertises it once its probe passes through the gateway; nothing else to
  set. It trusts the PROXY header from the gateway's address only
  (`SENSOR_MTLS_TRUSTED_PROXIES`); a PROXY header from any other peer closes
  the connection, so a sensor cannot choose the address it is recorded with.
- No public certificate is needed for the sensor endpoint: the API mints its
  server certificate (DNS or IP SAN) from the sensor CA and sensors pin that CA.
- Dedicated sensor host name as well (also reached by sensors that do not
  offer the id): `OPENCTEM_SENSOR_GATEWAY=passthrough SENSOR_PUBLIC_HOSTNAME=sensors.example.com
  SENSOR_PUBLIC_HOST=sensors.example.com:443` (`sensors/passthrough.wrappers`:
  routed by ALPN and by SNI).
- The gateway entrypoint refuses `alpn` or `passthrough` in TLS mode `http`
  or on an image without the layer4 module, and `passthrough` without
  `SENSOR_PUBLIC_HOSTNAME`, with a port in it or with the platform host name.
- A separate port, only when explicitly wanted: publish the API's 9443
  directly (or through any TCP load balancer) and set
  `SENSOR_PUBLIC_HOST=<host>:<port>`.
- With the stock gateway image nothing changes: the probe meets the gateway's
  own certificate and sensors use the HTTPS binding, whose `Subscribe` stream
  is flushed as it is written (`flush_interval -1` on every route to the API).
- `deploy/gateway/smoke-test.sh` builds the layer4 image and checks the ALPN
  and SNI routing next to the normal routing.

## Deploying without our gateway

The deployment-mode matrix is RFC-059 §5.1. Without our gateway there are
three ways to keep one port, and one automatic fallback.

### The API terminates TLS itself (one port, no proxy)

For an API exposed directly (the web console deployed on its own, or no web
at all) or behind a TCP load balancer:

```bash
SERVER_TLS_CERT_FILE=/certs/api.crt     # PEM, full chain first
SERVER_TLS_KEY_FILE=/certs/api.key
SENSOR_PUBLIC_API_URL=https://api.example.com   # what sensors and the probe dial
```

- The API listener (`SERVER_PORT`) then speaks TLS (1.2 or later, h2 and
  HTTP/1.1) with that certificate. In the handshake
  (`tls.Config.GetConfigForClient`) a ClientHello that offers the ALPN id
  `openctem-sensor/3` gets the mTLS listener's own TLS config instead and is
  served by the mTLS listener's server: client certificate from the sensor
  CA required and resolved through the key table at the handshake and again
  on every call, `h2` only. A connection that offers the id without a valid
  certificate is refused, exactly as on `:9443`.
- The endpoint is derived from `SENSOR_PUBLIC_API_URL` (else `APP_URL`) and
  advertised as `grpc_alpn_endpoint` once the self-probe passes; nothing else
  to set. `:9443` still listens and need not be published.
- The certificate files are checked every minute and re-read when they
  change; a renewal that does not load keeps the previous certificate.
- Everything that called the API over plain HTTP (the web server's API
  origin, health checks) must use `https://` on that port.
- A TCP load balancer in front that sends PROXY protocol v2: list its
  addresses in `SENSOR_MTLS_TRUSTED_PROXIES`. The header comes before the
  ClientHello, so it is then believed for API clients on that port too; from
  any other peer a PROXY header closes the connection.
- Unset (the default), the API serves plain HTTP behind whatever terminates
  TLS, exactly as before.

### An own TLS proxy that routes by ALPN at layer 4

The proxy reads the ClientHello without terminating it and sends a
connection that offers `openctem-sensor/3` to the API's mTLS listener
(`:9443`), everything else to the service that terminates TLS for the web UI
and the API. Both examples below were run against the mTLS listener
(sensor with a certificate served, without one refused, browsers on h2 served
by the HTTPS backend, the probe advertising `grpc_alpn_endpoint`); a sensor
offers `h2` first, so match the id anywhere in the list.

nginx (`stream` module with `ssl_preread`, in the official image;
`$ssl_preread_alpn_protocols` is the comma-separated list the client
offers):

```nginx
stream {
    map $ssl_preread_alpn_protocols $openctem_backend {
        ~(^|,)openctem-sensor/3(,|$)  api.internal:9443;
        default                        web-tls.internal:443;
    }
    server {
        listen 443;
        ssl_preread on;
        proxy_pass $openctem_backend;
    }
}
```

nginx's `proxy_protocol on` applies to every backend of the `server` block:
either leave it off (the API then records the proxy's address for sensors)
or make every backend accept PROXY v2 and list the proxy in
`SENSOR_MTLS_TRUSTED_PROXIES`.

HAProxy (`mode tcp`, `req.ssl_alpn` matches any offered id; PROXY v2 per
backend):

```haproxy
frontend openctem
    mode tcp
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend openctem_sensor if { req.ssl_alpn openctem-sensor/3 }
    default_backend openctem_https
backend openctem_sensor
    mode tcp
    server api api.internal:9443 send-proxy-v2   # SENSOR_MTLS_TRUSTED_PROXIES = this proxy
backend openctem_https
    mode tcp
    server web web-tls.internal:443
```

### SNI-only passthrough (a dedicated sensor host name)

A router that reads only the server name (a Kubernetes ingress-nginx
controller started with `--enable-ssl-passthrough` and the
`nginx.ingress.kubernetes.io/ssl-passthrough: "true"` annotation, or the
`req.ssl_sni` rule in HAProxy, tested) cannot route by ALPN and cannot
route an IP address. Give sensors their own name that the router passes to
the API's `:9443`, and set `SENSOR_PUBLIC_HOST=sensors.example.com:443`. The
probe then passes with and without the id, so hello names the endpoint as
`grpc_endpoint` and `grpc_alpn_endpoint`. The passthrough backend of
ingress-nginx is the Service's cluster IP, so `SENSOR_MTLS_TRUSTED_PROXIES`
stays empty there (no PROXY header).

### L7-only load balancers

A balancer that terminates TLS and cannot pass TCP through needs nothing:
the probe meets its certificate (`foreign_certificate`), nothing is
advertised, and sensors use the HTTPS binding (`/api/v3/sensor`) through it.
Keep response buffering off for that path so the `Subscribe` stream flows.

## How the bindings are chosen

No operator switch turns a binding on. `SENSOR_TRANSPORT_V3` is `auto` by
default; `off` is the emergency switch (no v3 at all; every sensor is back on
v2 at its next call).

- The HTTPS binding (`/api/v3/sensor`, through the normal TLS termination) is
  always served: it reuses the v2 edge chain and needs nothing new.
- The gRPC binding listens once the sensor CA loads (created on first start in
  `SENSOR_MTLS_CA_DIR` when no CA files are given) and a public host is known:
  `SENSOR_PUBLIC_HOST`, else the host and port of the platform URL
  (`SENSOR_PUBLIC_API_URL`, else `APP_URL`, https only), a name or an IP
  address alike.
- A self-probe dials the public host every minute (every 30 s while failing):
  TLS 1.3 offering the ALPN ids `h2` and `openctem-sensor/3` like a sensor,
  server certificate verified against the sensor CA only. Only the API's mTLS
  listener holds such a certificate, so the probe passes only when the path
  through the gateway reaches it. A passing probe is followed by one offering
  `h2` only. Hello names the endpoint as `grpc_endpoint` when both pass (a port
  of its own, a dedicated SNI host) and only as `grpc_alpn_endpoint` when just
  the first does (ALPN routing on the platform's port), so sensors that do not
  offer the id never dial an endpoint where they would meet the gateway's
  certificate. The v3 `Hello` RPC names `grpc_endpoint` only. A gateway
  without ALPN or SNI routing, a closed port or a wrong name fail the probe
  (`foreign_certificate`, `unreachable`, `dns_failed`, `handshake_failed`,
  `http2_refused`), so a sensor is never sent to an endpoint that cannot work.
- Status: Console > Operations (`GET /api/v1/admin/operations`, field
  `sensor_transport`; platform admins only, installation infrastructure that
  organization users never see) answers the mode, the HTTPS path and the gRPC
  state, endpoint, `requires_alpn`, reason and last check. The page shows a
  plain-language note per reason, only when an operator can change
  something; metrics
  `openctem_sensor_transport_grpc_advertised` (0/1) and
  `openctem_sensor_transport_grpc_probe_total{result}` (`ok`, `ok_alpn`, or
  the failure reason); the API logs each
  change of state.

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
