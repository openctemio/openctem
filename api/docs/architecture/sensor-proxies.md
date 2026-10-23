# Sensor proxies (proxy pools)

> RFC: [RFC-034](../rfcs/RFC-034-sensor-network-egress.md) §0 (amendment
> 2026-10-21). Vocabulary: [sensors.md](sensors.md). Job signing:
> [job-signing.md](job-signing.md).

A **proxy pool** is an organization's list of upstream proxies for scan
traffic. Sensors run every tool connection of a scan or retest job through
the pool from their per-task forwarder, after the forwarder's scope check, and
report what they saw; the platform scores each endpoint, quarantines dead ones
and re-admits them after a back-off. The sensor's own link to the platform
and its content downloads stay sensor-local (`SENSOR_CONTROL_PROXY`,
`SENSOR_CONTENT_PROXY`): a pushed value that is wrong would cut a sensor off.

## Which pool a job uses

| Order | Source | Applies to |
|---|---|---|
| 1 | Sensor-local veto: `SENSOR_SCAN_EGRESS=direct-only` (refuses jobs carrying a pool) and `SENSOR_SCAN_EGRESS_ALLOW` (the only upstreams it accepts) | the host operator decides; the platform cannot override |
| 2 | The sensor's assignment (`PUT /api/v1/proxy-pools/assignments/{sensor_id}`): Direct or a pool | a pool here carries **all** target addresses (a segment proxy) |
| 3 | The organization default pool (`is_default`, at most one) | **public** target addresses only; private, ULA and CGNAT targets are dialed directly, so internal targets never reach an external proxy |
| 4 | none | today's behaviour |

A disabled pool is not used (its sensors scan directly). Shared (operator)
sensors never use an organization pool.

## Data model (migration `sensor_proxy_pools`)

| Table | Purpose |
|---|---|
| `proxy_pools` | `tenant_id`, `name` (unique per tenant), `enabled`, `is_default` (partial unique index: one per tenant), `strategy` (`sticky` or `priority`), `revision` (bumped on every change a sensor sees). |
| `proxy_endpoints` | One row per proxy: `scheme`, `host`, `port`, `label`, `priority` (paste order), `enabled`, `credentials_encrypted` (AES-GCM under `APP_ENCRYPTION_KEY`, plaintext `{"t":tenant,"e":endpoint,"u","p"}` so a ciphertext copied to another row does not open), and the health columns (`state`, `score`, `success_ewma`, `consecutive_failures`, `probation_ok`, `quarantine_count`, totals, `handshake_ms_p95`, `last_error`, `last_ok_at`, `last_failure_at`, `quarantined_until`). Composite FK `(tenant_id, pool_id)`. |
| `proxy_sensor_assignments` | `sensor_id` (PK), `tenant_id`, `mode` (`direct` or `pool`), `pool_id`. Composite FKs `(tenant_id, sensor_id)` → `sensors` (so a sensor of another tenant, or a shared sensor with no tenant, cannot be assigned) and `(tenant_id, pool_id)` → `proxy_pools` with `ON DELETE RESTRICT` (a pool in use cannot be deleted: `409 PROXY_POOL_IN_USE`). No row: inherit. |

Code: `pkg/domain/proxypool` (validation, paste list, health, job egress),
`internal/app/proxypool` (service), `internal/infra/postgres/proxy_pool_repository.go`,
`internal/infra/http/handler/proxy_pool_handler.go` (console API),
`internal/infra/http/handler/sensor_egress_v2_handler.go` (sensor API),
`internal/app/command/egress.go` (delivery and the fail-closed gate).

## Console API

| Route | Permission |
|---|---|
| `GET /api/v1/proxy-pools`, `GET /{id}`, `GET /assignments` | `sensors:egress:read` |
| `POST /api/v1/proxy-pools` `{name, description, strategy, enabled, is_default, endpoints_text}` | `sensors:egress:write` |
| `PATCH /api/v1/proxy-pools/{id}` `{name, description, strategy, enabled, is_default}` | `sensors:egress:write` |
| `PUT /api/v1/proxy-pools/{id}/endpoints` `{text}` | `sensors:egress:write` |
| `PATCH /api/v1/proxy-pools/{id}/endpoints/{endpoint_id}` `{enabled, reset_health}` | `sensors:egress:write` |
| `PUT /api/v1/proxy-pools/assignments/{sensor_id}` `{mode: inherit|direct|pool, pool_id}` | `sensors:egress:write` |
| `DELETE /api/v1/proxy-pools/{id}` | `sensors:egress:delete` |

Owner and admin hold all three; write and delete are admin-only (no custom
role). Limits: 20 pools per organization, 64 endpoints per pool, a 64 KiB list.

**Paste list.** One `scheme://[user:pass@]host:port[#label]` per line; blank
lines and lines starting with `#` are ignored; characters special in a URL
must be percent-encoded in a user name or password. The same scheme, host
and port keeps the endpoint's id and health; a removed line deletes its
endpoint; a new line starts in probation. Responses carry `has_credentials`
and `credentials_updated_at`, never a credential; `endpoints_text` shows a
stored credential as `••••`, and a line that keeps `••••` keeps it. New
credentials reset the endpoint's health. An invalid line answers
`400 INVALID_PROXY_ENDPOINT` with its line number and never repeats the line.

**Endpoint validation.** Schemes `http`, `https`, `socks5`, `socks5h`; a host
name or an IP address; port 1–65535. Refused: loopback, link-local
(169.254.0.0/16, fe80::/10, including cloud metadata), `fd00:ec2::254`,
`100.100.100.200`, `168.63.129.16`, multicast, unspecified, broadcast, 0.0.0.0/8, 240.0.0.0/4,
`localhost`, `*.localhost`, `metadata`, `metadata.google.internal`. Private
addresses are allowed: a proxy into a segment usually is one. The sensor
checks every address a host name resolves to again before it dials.

## Delivery and signing

When an organization sensor receives a scan or retest job (claim-N poll, the
plain poll, a claim by id, and the claim repeat that a signing sensor runs),
`internal/app/command/egress.go` sets the payload member on the copy it hands
out:

```json
"egress": {"mode": "pool", "pool_id": "…", "revision": 7, "strategy": "sticky",
  "applies_to": "public",
  "endpoints": [{"id": "…", "scheme": "socks5", "host": "10.0.0.5", "port": 1080, "weight": 0.81, "auth": true}]}
```

Only enabled endpoints that may carry traffic now are listed, in priority
order; `weight` is the platform's (score² when healthy, 5 % of that in
probation). The member is part of the payload, so the statement's
`payload_sha256` covers it. A member a command's creator put in the payload
is replaced or removed, also on shared sensors.

**Fail closed.** A sensor whose jobs use a pool gets scan and retest jobs
only when it reported `egress.upstream@1` and `net.confined@1` (what the
sensor reports, never what an administrator declares); otherwise the poll
leaves them pending (metric reason `egress_unsupported`) and a claim by id
answers `command-claimed`. When every endpoint is quarantined the member
still goes out with an empty list and the sensor fails the job
(`egress_unavailable`); it never goes direct.

## Sensor API

Both under `/api/v2/sensor/commands/{command_id}/`, header
`X-OpenCTEM-Lease-Epoch`, v2 HTTPS only (protocol v3 does not carry them):

- `POST egress-credentials` `{pool_id}` → `{credentials: [{endpoint_id, username, password}]}`
  with `Cache-Control: no-store`. Answered only to the sensor holding the
  command's live lease (acknowledged or running, matching epoch), only for
  the pool its jobs use now. Everything else is `404 command-not-found`.
  Never logged, never stored with the command.
- `POST egress-report` `{pool_id, endpoints: [{endpoint_id, ok, proxy_down, proxy_auth,
  target_unreachable, target_refused, handshake_ms_p50, handshake_ms_p95, last_error}]}` → 204.
  From the sensor the command is assigned to (while it runs and up to 15
  minutes after it ended), at most 64 endpoints; the pool must be the one
  that sensor's jobs use now (a sensor never moves the health of another
  pool, even one of its own organization); unknown endpoints are ignored; `last_error` is sanitized again (one line, 200 characters, URL
  user information removed).

## In the sensor

sdk-go `pkg/sensorkit/egress/upstream` plugs the pool into the per-task
forwarder's dial hook: HTTP CONNECT, HTTPS (proxy certificate verified) and
SOCKS5 tunnels, always to the address the forwarder already checked. `sticky`
keeps each target host of a job on one endpoint by weighted rendezvous
hashing (removing an endpoint moves only its hosts); `priority` follows the
list. Only a proxy that is down fails over (at most once per endpoint); a
proxy authentication failure takes the endpoint out for the job; a local
breaker per endpoint opens after 3 consecutive failures. What does not use
the pool: DNS (resolved and pinned on the sensor), UDP (the forwarder
carries TCP only), content downloads and code-scan source fetches (content
path); a naabu SYN scan, tools in process, an unconfined sandbox, CI runner
mode and shared sensors refuse a job carrying a pool. An HTTP CONNECT proxy
must allow CONNECT to the scanned ports (many allow only 443); SOCKS5 has no
such limit.

## Health

Per endpoint, from sensor reports (`pkg/domain/proxypool/health.go`):

- success average: EWMA of `ok / (ok + proxy_down)`, half-weight every 20 connections;
- latency: `clamp(1 - (p95_ms - 200) / 2000)`;
- score `= clamp(0.8·success + 0.2·latency − 0.15·min(consecutive failed reports, 4))`.

| State | Enter | Leave |
|---|---|---|
| probation | new endpoint, credentials changed, health reset, or back from quarantine | 20 clean connections and score ≥ 0.6 → healthy |
| healthy | as above | score < 0.3 or 3 failed reports in a row → quarantined |
| quarantined | score < 0.3, 3 failed reports in a row, or a proxy authentication failure without success | back-off 5 min, doubling to 2 h; then eligible again in probation: the next job's real traffic is the re-probe; a success keeps it in probation, a failure quarantines it again with a doubled back-off |

Target errors (CONNECT 502/504/403, SOCKS replies 2–6) never count against a
proxy. The platform never probes a proxy itself (it cannot reach internal
proxies and would become an SSRF tool). The numbers are internal defaults,
not settings. Quarantining is audited (`proxy_pool.endpoint_quarantined`).

## Threat model

| Threat | Control |
|---|---|
| Credential leak (database, API, logs, job payload) | Encrypted at rest and bound to tenant and endpoint; never in a response, the audit log, an error or the job payload; fetched per job by the lease holder only; the sensor keeps them in the forwarder's memory and tools never see them (they talk to the task relay). |
| Tenant A's pool used for tenant B | Every query is tenant-scoped; composite foreign keys; credentials only for the pool the claiming sensor's tenant set for it; shared sensors never get an organization pool. |
| Proxy endpoint as SSRF (metadata, loopback, the operator's services) | Deny list at save; the sensor re-checks every resolved address at dial. Private addresses are allowed for organization sensors (the organization's own network). |
| A proxy widens what a job reaches | The forwarder checks the target (scope, pinned addresses, port and path limits) before the upstream dial and connects by the checked address; the proxy only carries an admitted connection. |
| Compromised platform points scans at an attacker's proxy | The pool is in the signed payload; the sensor-local `SENSOR_SCAN_EGRESS=direct-only` and `SENSOR_SCAN_EGRESS_ALLOW` pin what a host accepts. A signer-ledger check of the pool is later work. |
| Malicious or intercepting proxy | TLS to an `https://` proxy is verified; target TLS is unchanged (the tool decides). Third-party trust marking is later work. |
| Silent change | Audit on pool create/update/delete, endpoint list and credential changes, endpoint enable/disable/reset, sensor network path, quarantine. |
| Unconfined sensor goes direct | Pool jobs only to sensors reporting `egress.upstream@1` and `net.confined@1`. |
| Score poisoning by a hostile sensor | A report counts only from the sensor holding the job's lease, only for the pool that sensor's jobs use now, and only up to 15 minutes after the job ended; it can never touch another organization's pool or another pool of its own organization; a sensor never uses an endpoint the platform quarantined. |

## Not built yet

Credentials sealed to the claiming sensor's key (today they travel in the
clear inside the sensor's TLS connection, so a TLS-inspecting proxy on the
sensor's control path can read them), one report per job, zone pools,
tool rules (pool / direct / refuse), per-scan override,
instance pools offered to tenants, exit-IP attribution, `dns=proxy`, the
Test button, a reason on the sensor page when a sensor lacks proxy support,
and pools for validation and reach-probe jobs (they run without a pool).
