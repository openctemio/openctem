# Sensor ↔ platform trust

> Design: [RFC-040](../rfcs/RFC-040-platform-sensor-mutual-distrust.md). Related:
> [sensors.md](sensors.md), [agent-identity.md](agent-identity.md),
> [sensor-pairing.md](sensor-pairing.md), [sensor-result-binding.md](sensor-result-binding.md),
> [scan-zones.md](scan-zones.md), RFC-023, RFC-031, RFC-032, RFC-034, RFC-038,
> RFC-052.

The goal is **mutual distrust**: compromising one side must not be enough to
exploit the other.

- A compromised sensor (or a stolen sensor key) must not be able to attack the
  platform or other tenants.
- A compromised platform (web, API or database) must not be able to weaponize
  sensors against targets their network owner did not allow.

## Controls

The controls are grouped as in RFC-040. Each row names where the control lives;
the RFC holds the design and phase plan.

### Sensor → platform

| Control | Where |
|---|---|
| Per-sensor identity, short-lived self-renewed keys, instant revocation | [agent-identity.md](agent-identity.md); key-bound identity and pairing: RFC-032, RFC-052, [sensor-pairing.md](sensor-pairing.md) |
| Tenant taken from authentication, never from the request body | sensor authenticator on `/api/v2/sensor/*` |
| Sensor credentials accepted only on sensor routes, user credentials only on user routes | `internal/infra/http/routes/sensor_v2.go`, `middleware/apikey_auth.go` |
| Per-sensor job authorization: poll and claim scoped by tenant, sensor pin, zone, tool and capability; per-sensor grants | [scan-zones.md](scan-zones.md), RFC-052 |
| Results bound to the job that produced them; unsolicited reports limited or quarantined | [sensor-result-binding.md](sensor-result-binding.md) |
| Strict result parsing: schema validation, size, depth and item limits checked before decoding, string sanitisation, output encoding in the console, tickets and notifications | `pkg/sensorproto/v2`, `internal/app/ingest`, [web security architecture](../../../web/docs/security-architecture.md) |
| Separate sensor gateway and isolated ingest workers | **Planned** (RFC-040 §5.1, §5.4) |

### Platform → sensor

| Control | Where |
|---|---|
| Declarative jobs only, never shell; signed custom-template manifests | sdk-go command poller; RFC-040 §5.8 |
| Platform-side scope check before dispatch; scan targets limited to what the actor may act on | [active-probe-gate.md](active-probe-gate.md) |
| Sensor-local, read-only policy set by the network owner (allowed ranges, ports, check types, kill switch); the platform stops dispatching jobs a sensor would refuse | [sensors.md](sensors.md#sensor-local-policy-rfc-040-57) |
| Scan credentials held by the sensor, referenced by the platform | RFC-040 §5.9, RFC-032 |
| Jobs signed by a separate signing service, with nonce and sequence against replay | **Planned** (RFC-040 §5.6) |
| Two-person approval for scope widening | **Planned** (RFC-040 §5.6) |

### Both directions

| Control | Where |
|---|---|
| Audit of scope, exclusions, tools, scanner templates, scans and commands; tamper-evident audit chain | [audit-hash-chain.md](audit-hash-chain.md) |
| Hardened sensor images (non-root, minimal) and install snippets | sensor repository, RFC-040 §5.10 |
| Anomaly alerts on scope changes and unusual sensor activity | **Planned** (RFC-040 §5.11) |

### Outbound-only (invariant)

Sensors never accept inbound connections; all control flows over the
sensor-initiated, authenticated channel (RFC-040 §11.1). The sensor binds
nothing reachable from the network (per-task relays bind loopback inside a
private network namespace, the egress forwarder uses Unix sockets, images
expose no port); a regression test in the sensor repository fails the build
when the binary listens on a non-loopback address.

## Sensor → platform input review (2026-10-08)

Every input a sensor can send, on `develop` 6684c011b with sdk-go `main`
2e008ba and sensor `main` 31394db, assuming the sensor and the tools inside it
are hostile. Decisions and the full finding list: RFC-040 §11.

### Inventory

| Input | Code | Tenant and sensor from | Object binding | Limits |
|---|---|---|---|---|
| v2 results: `PUT /results/{id}`, segments, commit, status, abandon (also under `/commands/{cid}/…`) | `handler/sensor_results_v2_handler.go`, `ingest/v2_receiver.go`, `ingest/quarantine.go` (`OpenCommand`) | authenticated identity | `(tenant, sensor, report_id)`; a named command must be the sensor's and open | 16 MiB wire, 64 MiB decoded, ratio 100, depth 64, item bounds before decode; 10/s per sensor, 20/s and 8 concurrent per tenant; staging purged |
| heartbeat, manifest, config report | `handler/sensor_control_v2_handler.go`, `app/sensor/manifest.go`, `config_report.go` | identity | the sensor's own row | 1 MiB / 256 KiB / 64 KiB; 10/s per sensor |
| poll, claim, start, complete, fail, release, logs | `postgres/command_repository.go`, `command_lease.go`, `app/commandlog` | identity | tenant + pin, zone, tool, capability, grant; fenced by lease epoch | 4 MiB completion; logs 256 KiB per batch, 2 MiB per command, 14 days |
| fingerprints check, baseline diff, suppressions | `ingest/service.go`, `sensor_control_v2_handler.go` | identity tenant | tenant-wide (to be narrowed to the sensor's zone and grant) | 8 MiB, 50k fingerprints |
| key renewal | `routes/sensor_v2.go` | identity | the presented key | burst 5, then one per 2 minutes |
| validation evidence `POST /api/v1/validation/evidence` | `handler/validation_handler.go` | identity | the validate command assigned to the sensor | 10 MB |
| CI uploads `/api/v1/ci/runs/{id}/*` | `handler/ci_runner_handler.go` | run token (OIDC exchange) | the run's repository | 100 MB decompressed, bounded decode |
| protocol v3 (HTTPS and gRPC) | `sensortransport/*`, `handler/sensor_v3_bridge.go` | signature or certificate → key row; SAN must match | the v2 routes in process, same budgets | per-IP limit, 256 unary in flight per replica before authentication, 17 MiB message, 4 streams per sensor |
| pairing `/api/v2/sensor/pairings/*` | `handler/sensor_pairing_handler.go`, `app/sensorpairing` | proof of possession of the key | `(pairing_id, thumbprint)` | 10/h per IP, 600/h global, 1/s per pairing (keyed on the parsed id) |
| wake bus `sensor:v3:wake` | `redis/sensor_wake.go` | sensors cannot publish | UUIDs only, 512 bytes | bounded queue |

### Verified controls

- Strict RFC 9421 parsing (one signature, fixed components, byte-exact
  parameters, ed25519 only, nonce spent after verification in Redis, 5 minute
  window plus 2 minutes skew, body digest on every write); no keyid or
  algorithm confusion; bearer keys refused for key-bound sensors.
- mTLS: TLS 1.3, client certificate required, certificate key must be an active
  registered key and its SPIFFE SAN must match the row, on the handshake and on
  every request; PROXY headers only from configured addresses.
- The in-process v2 router of protocol v3 is never on a listener; v3 ids are
  validated as UUIDs before they become path segments.
- Command transitions fenced by tenant, sensor, status and lease epoch;
  completion side effects take the finding, run and tenant from the stored
  command, never from the sensor's result.
- Ingest: provenance from the stored report; unsolicited reports never change
  existing assets; reserved tool names and protected finding sources cannot be
  claimed; the CVE catalog and risk signals come only from feeds.
- Scope auto-join of discovered names never widens scan authority: dispatch
  still requires a covering scope entry, domain proof never comes from sensor
  data, and chained step targets pass the full dispatch gate.
- Output: no HTML sinks in the web console, scanner text never rendered as
  markdown, nonce CSP, encoded tickets and notifications; outbound HTTP through
  the SSRF-safe client; Prometheus labels never taken from sensor input.

### Status of the findings

| # | Finding | State |
|---|---|---|
| C1 | Result bodies decoded before their item limits | fixed: bounded pre-pass, #1553 |
| H1 | v3 HTTPS binding skipped the global guards | fixed: #1557 |
| H2 | Coverage auto-resolve outside the command | fixed: #1551 |
| H3 | Pairing limiter keyed on the raw path | fixed: #1559 |
| H4 | Ingest staging never purged | fixed: #1561 |
| H5 | Unsigned jobs, no policy by default, platform TLS not pinned | decided (RFC-040 Q3 revised, Q10, Q11); sdk-go, sensor and signer work |
| H6 | Unconfined sandbox and DNS rebinding past admission | decided (RFC-040 Q12); sdk-go and sensor work |
| M1 | Scan-zone preview resolved any name | fixed: #1564 |
| M3 | Jira comments carried live wiki markup | fixed: #1562 |
| M4 | Scan name injection into CI snippets | fixed: #1563 |
| M | Per-tenant quotas, v3 per-sensor in-flight bound and connection cap, global decoded-bytes budget, manifest history, per-tenant control budget, sharded nonce store, pairing IPv6 grouping and expected-organization pin, source-resolve tool rule, findings outside command scope | open |
| L | v3 CI-OIDC policy, bearer regeneration under key-bound-only, signed v2 body limit, tenant-wide fingerprint and suppression lookups, timestamps and discovery source, relationship edges, reachability claims, CSV whitespace, Telegram parse mode, BFF header pass-through, ssh dial pinning, NAT64 ranges, pending quarantine age-out, wake and stream-open rate limits | open |

## Reporting a weakness

Report a suspected weakness in these controls privately, as described in the
[security policy](../../../SECURITY.md).
