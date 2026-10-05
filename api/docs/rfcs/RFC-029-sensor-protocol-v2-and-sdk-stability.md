# RFC-029 — Sensor protocol v2 for the whole sensor surface, and a stable SDK

> Status: **Accepted** (product owner, 2026-10-02: "move sensors fully to v2
> now, so we can start phasing out agent"; one release, one announcement).
> **Protocol v1 retired 2026-10-05** (owner: young product, minimal back-compat):
> the live API served 3,303 `/api/v2/sensor/*` and 0 `/api/v1/agent/*` requests
> in the preceding 24 hours, so the v1 routes, the `/api/v1/agents` redirect and
> `pkg/sensorproto/legacyv1` were removed ahead of the 2027-04-01 sunset.
> Sensors older than v0.9.0 must be upgraded.
> Scope: api + sdk-go + sensor (`openctemio/sensor`, local checkout `agent`).
> Builds on: [RFC-023](RFC-023-scan-zones-and-scanners.md) (sensors, §9.2
> C1–C8 compatibility contract, §9.2a doorbell, §9.2b suppressions, D20/D24),
> [RFC-023 rename contract](RFC-023-sensor-rename-contract.md) and
> [RFC-026](RFC-026-sensor-results-ingest.md) (v2 results, which this RFC
> does not change). Operator view: [architecture/sensors.md](../architecture/sensors.md).
>
> Owner's questions:
> - **A.** "Why does sdk-go still use `/api/v1/agent/ingest` and the
>   `X-Agent-ID` header? I thought it moved to sensor."
> - **B.** "When the SDK updates later, sensors that already implemented it
>   should need as few changes as possible: bump the SDK version and done."

## 1. Answers in short

**A.** Only results moved. RFC-026 built v2 for *results* (`PUT
/api/v2/sensor/results/…`) and `GET /api/v2/sensor/hello`; everything else a
sensor does is still protocol v1, because v1 is frozen for deployed sensors
(RFC-023 C1) and no v2 resource existed for it. In sdk-go `main` (v0.8.1) the
v1 calls are: heartbeat (`pkg/client/client.go:560`), v1 ingest fallback
(`:494`), ingest check (`:673`), baseline-diff (`:732`), chunk (`:1403`),
suppressions (`:1512`), command poll/acknowledge/start/complete/fail
(`pkg/client/command.go:37,93,105,121,143`) and key renewal
(`pkg/platform/client.go:90`). `X-Agent-ID` is set on every v1 request
(`client.go:867`, `platform/client.go:99`), but **the API never reads it**:
`git grep X-Agent-ID` on api `develop` finds no reader; identity comes from
the key. The header is dead weight that leaks the old vocabulary.

This RFC finishes the move: every sensor resource gets a v2 path under
`/api/v2/sensor/*`, identity comes only from the key, the SDK uses v2 for
everything the platform offers, and v1 is served but **deprecated** with
`Deprecation` / `Sunset` headers and per-sensor usage telemetry.

**B.** Today a sensor is an *assembler* of SDK parts. Our own sensor imports
17 SDK packages and about 145 distinct exported symbols from 20 non-test
files, and `runDaemon` alone wires 15 SDK objects by hand (base sensor,
parsers, asset resolver, doorbell, key renewal, auth gate, executor, scan
policy, poller, outbox, …). So every SDK feature has needed sensor code:
doorbell (sensor#66, +305 lines), auth backoff (#72, +184), key renewal
(#35, +92), outbox + v2 results (#76, +810), dispatched-findings delivery
(#62, +753). The release bumps themselves look harmless (8 of the last 9
touched only go.mod/go.sum) only because the adapting code had already landed
in those feature PRs, built against SDK pseudo-versions. The fix
is a small **facade** that owns the runtime (§8.3), interfaces that grow by
optional interfaces instead of new methods (§8.4), an **API-compatibility
gate** in sdk-go CI (§8.6) and capability-gated server behaviour (§8.8).
What lands in this release and what later is marked in §8.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | Every sensor resource has a v2 path under `/api/v2/sensor` (§4): `hello`, `heartbeat`, `commands` (poll, claim, start, complete, fail), `suppressions`, `fingerprints/check`, `fingerprints/baseline-diff`, `keys`, and the RFC-026 `results`. |
| D2 | **Identity is the key, nothing else.** No `X-Agent-ID` on v2: the SDK does not send it and the server ignores it (as v1 already does). No other identity header is defined. |
| D3 | v2 handlers call **the same application services** as v1 (`command.Service`, `SensorService`, `ingest.Service`, `suppression.Service`, `Doorbell`). Only the wire differs. |
| D4 | v2 is JSON with RFC 9457 problems; control-plane bodies are decoded **leniently** (unknown members ignored) and clients **must ignore** unknown response members. CTIS results stay strict (RFC-026). This is what lets a newer SDK talk to an older v2 server and the reverse. |
| D5 | **Command transitions are idempotent**: repeating the transition that produced the current state, by the same sensor with the same body, answers `200` with the current command and no side effects. Different body → `409`. |
| D6 | **Negotiation per feature**: `GET /hello` lists the features this server serves on v2; the SDK uses v2 for a listed feature and v1 for an unlisted one. An API from before this RFC (`features: ["results"]`) therefore gets v2 results and v1 for the rest, and an API without v2 gets v1 throughout. |
| D7 | **v1 is deprecated, not removed.** Every v1 sensor route that has a v2 successor answers with `Deprecation: @1790812800` (2026-10-01), `Sunset: Thu, 01 Apr 2027 00:00:00 GMT` and `Link: <successor>; rel="successor-version"`. Bodies and status codes do not change (C1, golden-tested). Removal needs the measured criteria of §5.4, not just the date. |
| D8 | **Telemetry per sensor**: the heartbeat records the protocol it arrived on and the `User-Agent` (SDK and sensor version) on the sensor row; the Sensors API returns it, so the UI can show "still on v1". A counter per protocol and route gives the fleet view. |
| D9 | Release train: **api v0.9.0, sdk-go v0.9.0, sensor v0.5.0**, announced together (§10). sdk-go v0.9.0 has **no breaking change** to its exported API (the `pkg/retry` removal planned for v0.9.0 moves to v0.10.0). |
| D10 | SDK stability (§8): this release adds the API-compatibility gate and the sensor-compat build to sdk-go CI; the facade, `internal/` moves and the v1.0.0 commitment follow in later releases. |

## 3. The surface today (verified 2026-10-02)

API `develop` (`internal/infra/http/handler/testdata/protocol_v1/routes.golden`)
serves 24 v1 sensor routes. What the SDK and our sensor actually call:

| v1 route | Caller (sdk-go `main`) | Used by our sensor |
|---|---|---|
| `POST /api/v1/agent/heartbeat` (+ `X-OpenCTEM-Sensor-Features: doorbell, results-v2`) | `client.sendHeartbeat` | daemon heartbeat, doorbell, start-up connection test |
| `GET /api/v1/agent/commands?limit=n` | `client.PollCommands` | `core.CommandPoller` |
| `POST /api/v1/agent/commands/{id}/acknowledge`, `/start`, `/complete`, `/fail` | `client.AcknowledgeCommand` … `FailCommand` | poller and executor |
| `GET /api/v1/agent/suppressions` (fallback `/api/v1/suppressions/active`) | `client.GetSuppressions` | CI security gate (`-fail-on`) |
| `POST /api/v1/agent/ingest/check` | `client.CheckFingerprints` | outbox de-duplication |
| `POST /api/v1/agent/ingest/baseline-diff` | `client.BaselineDiff` | PR gate |
| `POST /api/v1/agent/renew` | `platform.PlatformClient.RenewKey` | daemon key auto-renew |
| `POST /api/v1/agent/ingest`, `/ingest/chunk` | `client.PushFindings` (v1 fallback), `chunk.Manager` | results when v2 is not offered |
| `GET /api/v2/sensor/hello`, `PUT /api/v2/sensor/…/results/…` | `client` v2 results | results (since sdk-go v0.8.0) |

Not called by the SDK (curl users, docs, older tools): `/ingest/sarif`,
`/ingest/recon`, `/ingest/scan`, `/ingest/ctis`, `/ingest/scanners`,
`/ingest/jobs/{id}`, `/scans` (scan sessions), `/telemetry-events`,
`/credentials/ingest`, `/api/v1/validation/evidence`.

`/api/v1/platform/{register,lease,poll,jobs/…}` (platform sensors,
`pkg/platform/{bootstrap,lease,poller}.go`) is **not served by the
open-source API** (no route on `develop`) and is out of scope; RFC-026 §10.1
already refuses tenant-less sensors on v2.

## 4. Protocol v2: the complete sensor surface

### 4.1 Rules for every v2 route

| Rule | Value |
|---|---|
| Mount | `/api/v2/sensor`, the existing group in `internal/infra/http/routes/sensor_v2.go`. Only the sensor authenticator runs there (RFC-023 C-2): user JWTs, cookies and `oct_` keys get `401`; sensor keys stay refused on user routes. |
| Authentication | Sensor key in `Authorization: Bearer <key>` or `X-API-Key: <key>`, as v1. RFC 9421 signing is RFC-023 Phase 3 and does not change these paths. |
| Identity | From the key only. `X-Agent-ID` is not sent and is ignored if present. |
| Tenant | From the key. A sensor without a tenant (platform sensor) gets `403 scope-denied` on every v2 route (RFC-026 §10.1). |
| Disabled sensor | `POST /heartbeat` answers `200` with `actions: ["pause"]` and writes nothing (every v2 sensor is doorbell-aware by contract); `GET /hello` stays readable so the sensor keeps negotiating v2. Every other route answers `401 unauthenticated`. Revoked sensor or expired key: `401` everywhere. |
| Request bodies (control plane) | `Content-Type: application/json` or absent; anything else is `415 unsupported-media-type` with `Accept: application/json`. Lenient decode: unknown members ignored; malformed JSON `400 invalid-request`. Max 1 MiB (`413 content-too-large`), except `complete` (4 MiB) and the fingerprint queries (8 MiB, for 50,000 fingerprints). |
| Responses | `Content-Type: application/json` on success, `application/problem+json` on error; always `OpenCTEM-Protocol: 2`. Clients must ignore unknown members. Timestamps RFC 3339 UTC. Ids lower-case UUID strings. |
| `User-Agent` | `openctem-sdk-go/<sdk version> (<binary>/<version>)` from sdk-go `pkg/useragent`; recorded (§5.3), never trusted. |
| Rate limits | Per sensor, on top of the per-tenant ingest budget: reads (`hello`, `commands` poll, `suppressions`) 5/s burst 20; writes (everything else) 10/s burst 20 (the existing v2 limiters). `429 rate-limited` + `Retry-After`. |
| Retry rule (client) | Retry `429`, `500`, `502`, `503`, `504` and network errors with exponential backoff + jitter, honouring `Retry-After`; never retry another `4xx`. Every v2 request is safe to retry under this rule (§4.10). |

### 4.2 `GET /hello`

Already served (RFC-026). Extended **additively**:

```json
{
  "protocol": 2,
  "features": ["results", "heartbeat", "commands", "suppressions", "fingerprints", "keys"],
  "media_types": ["application/vnd.openctem.ctis.v1+json"],
  "encodings": ["gzip", "zstd"],
  "digests": ["sha-256", "sha-512"],
  "limits": { "...existing RFC-026 limits...": 0,
              "max_control_body_bytes": 1048576,
              "max_fingerprints_per_request": 50000 },
  "deprecations": {
    "protocol_v1": { "deprecated_at": "2026-10-01T00:00:00Z", "sunset_at": "2027-04-01T00:00:00Z" }
  }
}
```

`features` is the negotiation (D6). A feature is listed only when every route
of that feature is mounted. Feature names are a closed, append-only set.
`200`; `401`; `403 scope-denied` (platform sensor); `429`.

### 4.3 `POST /heartbeat`

Request: the v1 heartbeat body, same member names (one Go type serves both):

```json
{ "name": "sensor-ci-01", "status": "running", "version": "0.5.0", "hostname": "ci-01",
  "message": "", "scanners": ["betterleaks","semgrep"], "collectors": [],
  "uptime_seconds": 3600, "total_scans": 12, "errors": 0,
  "cpu_percent": 3.5, "memory_percent": 21.0, "active_jobs": 1, "region": "eu",
  "disk_read_mbps": 0, "disk_write_mbps": 0, "network_rx_mbps": 0, "network_tx_mbps": 0,
  "outbox": { "pending_count": 0, "pending_bytes": 0, "oldest_age_seconds": 0,
              "dead_letter_count": 0, "evicted_count": 0 } }
```

All members optional; an empty body is a valid heartbeat. Same server-side
effects as v1 (`SensorService.UpdateHeartbeat`, IP from the connection under
the trusted-proxy rule, outbox snapshot rules of `architecture/sensors.md`),
plus the protocol telemetry of §5.3.

Response `200`:

```json
{ "sensor_id": "…", "tenant_id": "…", "status": "ok",
  "pending_jobs": 0, "next_heartbeat_seconds": 30,
  "actions": [], "config_version": "9f2c4e1ab07d3355" }
```

The doorbell is always on (`Doorbell.Ring` with `Aware: true`): every member
is always present (`pending_jobs` 0 and `actions` `[]` when there is nothing).
`status` is `ok`, or `paused` for a disabled sensor (then `actions:
["pause"]`, no other hint, no write). Actions are the closed set `pause`,
`resume`, `drain`, `rotate_key`, `update`; a client ignores one it does not
know. Errors: `401`, `403 scope-denied`, `413`, `415`, `429`.

#### 4.3.1 Sensor-reported capabilities (amendment, 2026-10-02)

Before this, a sensor's tools, capabilities and concurrency came only from
what an administrator typed when creating it. Dispatch then sent jobs to
sensors that lacked the tool, never sent jobs to sensors that had a tool
nobody declared, and could exceed the sensor's own concurrency. The heartbeat
(v1 and v2, same body) now carries the sensor's own report. All members are
optional and additive (§4.11 rule 1):

```json
{ "tools": [ {"name": "nuclei", "version": "3.3.0", "installed": true},
             {"name": "semgrep", "installed": false} ],
  "capabilities": ["nuclei", "dast", "validate"],
  "max_concurrent_jobs": 5, "os": "linux", "arch": "amd64" }
```

**The sensor's report is the truth, and the administrator can only narrow
it:**

| | effective (what dispatch uses) |
|---|---|
| tools | reported *installed* tools ∩ the sensor's `tools` (an empty `tools` allows every reported tool) |
| capabilities | reported ∩ the sensor's `capabilities` (likewise) |
| concurrency | min(reported, `max_concurrent_jobs`) |

`max_concurrent_jobs` in the report is the sensor's **configured cap**: the
most jobs it ever runs at once. Live free slots are separate. RFC-030's
`capacity` block reports them and bounds dispatch further (≤ the cap), so the
platform's capacity is min(admin limit, reported cap, live slots). The member
names here (`tools`, `capabilities`, `max_concurrent_jobs`, `os`, `arch`) are
stable.

- **A sensor that reports nothing keeps the administrator's values.** An absent
  list is "not reported". `[]` is "reported none", so that sensor gets no
  jobs for any tool.
- **Absent parts keep the stored report.** A heartbeat without the members, for
  example from an older SDK or a connection test, changes nothing. A
  downgraded sensor keeps its last report, and `reported_at` shows how old it is.
- **Untrusted input.** The server keeps only tool names that are in the tool
  catalog: active platform tools, or the sensor's tenant's own tools. It keeps
  only capabilities that are in the capability registry, name a known tool, or
  are `validate` / `validate:<known tool>`. Lists are capped at 64 entries and
  deduplicated. Names are lowercase `[a-z0-9._-]` (capabilities also allow
  `:`). Versions and the platform are reduced to safe tokens. Concurrency is
  clamped to 1..100. If the catalog cannot be read, the report is skipped and
  the heartbeat still succeeds.
- **Never widens.** Reporting cannot add a tool or capability the
  administrator excluded, raise the concurrency above the administrator's
  limit, or bypass scan-zone pinning (`zoneClaimPredicate` does not read it).
- **Scans go only to sensors that have the tool.** RFC-030's tool gate
  covers the command poll, the claim, the doorbell count and the zone
  predicate. It reads the effective tools (`sensorDispatchTools` in
  `command_repository.go`), so a command that names a tool (`scanner`, or a
  pipeline step's `preferred_tool`) reaches only sensors that report that
  tool installed and are allowed it. Zone routing uses the effective tools
  too.
- **Where it applies:** the selector (`FindAvailableWithCapacity`,
  `FindAvailableWithTool`, `FindByCapabilities`), `ClaimJob`, tool and
  capability availability (`GetAvailableToolsForTenant`, `HasSensorForTool`,
  `…Capabilities…`), the command poll's capability gate (v1 and v2), the
  sensor list filters and the platform capacity stats. The database computes
  the rule in generated columns `effective_tools`, `effective_capabilities`
  and `effective_max_jobs` (migration 000253). The domain computes it in
  `Sensor.Effective*`, and a DB test keeps the two in step.
- **Management API:** `GET /api/v1/sensors[/{id}]` keeps `tools`,
  `capabilities` and `max_concurrent_jobs` as the administrator's settings (the
  limits). It adds `reported` (null before the first report), `effective`, and
  `capability_mismatch` (`tools_not_installed`, `capabilities_not_reported`;
  omitted when there is nothing to show). On
  `PUT /api/v1/sensors/{id}`, a `tools` or `capabilities` list that is present
  replaces the limit, `[]` removes it, and an absent list leaves it as it is.
  Before this change, `[]` was ignored.
- **SDK:** sdk-go `core.CapabilityReporter` / `BaseSensor.SetCapabilityReporter`
  (asked on every heartbeat). `BaseSensor` always sends `os` and `arch`.

### 4.4 Commands

Representation (v2 `Command`; `sensor_id` replaces v1's `agent_id`):

```json
{ "id": "…", "type": "scan", "priority": "normal", "status": "acknowledged",
  "sensor_id": "…", "payload": { }, "created_at": "…", "expires_at": "…",
  "acknowledged_at": "…", "started_at": null, "completed_at": null,
  "error_message": "", "result": null }
```

`payload` is the command content as stored (its keys, including the job key
`agent_preference`, are command data, not protocol vocabulary).

| Method and path | Purpose | Success |
|---|---|---|
| `GET /commands?limit=n` | Commands this sensor may claim now (same predicate as v1 poll: pinned or unpinned, pending, not expired, zone claim predicate, capability gate). `limit` 1–100, default 10. | `200 {"commands": [Command…]}` |
| `POST /commands/{command_id}/claim` | pending → acknowledged (atomic claim; v1 `acknowledge`). Empty body. | `200 Command` |
| `POST /commands/{command_id}/start` | acknowledged → running. Empty body. | `200 Command` |
| `POST /commands/{command_id}/complete` | running → completed. Body `{"result": <any JSON>}` (optional). | `200 Command` |
| `POST /commands/{command_id}/fail` | acknowledged/running (or pending and pinned to this sensor) → failed. Body `{"error_message": "…"}` (≤ 4 KiB stored, UTF-8-safe truncation as v1). | `200 Command` |

Transition table (rows: current state; "mine" = the command's `sensor_id` is
the caller; another sensor's command is always `404 command-not-found`, so a
sensor learns nothing about other sensors' work):

| Current | `claim` | `start` | `complete` | `fail` |
|---|---|---|---|---|
| pending, unassigned | → acknowledged | 409 `invalid-transition` | 409 `invalid-transition` | 409 `invalid-transition` |
| pending, mine | → acknowledged | 409 | 409 | → failed |
| acknowledged, mine | **200 replay** | → running | 409 | → failed |
| running, mine | 409 | **200 replay** | → completed | → failed |
| completed, mine | 409 | 409 | **200 replay** if the result is semantically equal JSON, else 409 `transition-conflict` | 409 |
| failed, mine | 409 | 409 | 409 | **200 replay** if the stored message equals the (truncated) request message, else 409 `transition-conflict` |
| canceled / expired | 409 | 409 | 409 | 409 |

- A lost claim race (another sensor claimed the unassigned command between
  read and update, `ClaimForSensor` returned false) is `409 command-claimed`.
- Every `409 invalid-transition` carries the extension member `"state":
  "<current status>"`, so the SDK can drop a canceled or expired command
  without guessing.
- A **replay has no side effects**: pipeline progression, validation
  evidence and attack-simulation finalisation (`CommandHandler.Complete`
  triggers) run only on the real transition.
- Conditional requests: commands carry no `ETag` in this release. Each
  transition names its precondition (the state table), which is what
  `If-Match` would give a single writer; per-command versions arrive with
  leases (§4.11).

### 4.5 `GET /suppressions`

Response `200` (same document as v1 §9.2b):

```json
{ "count": 1, "rules": [ { "rule_id": "…", "tool_name": "semgrep",
  "path_pattern": "vendor/**", "asset_id": null, "expires_at": null } ] }
```

Strong `ETag` = first 16 hex characters of the SHA-256 of the body, quoted.
`If-None-Match` with the current tag → `304` and no body. Suppressions
module disabled for the tenant → `200` with an empty list. The SDK keeps the
rules and the tag in memory and revalidates.

### 4.6 Fingerprint queries

Both are read-only queries sent as `POST` because the list does not fit a
URL; both are safe to retry.

| Method and path | Request | Response `200` |
|---|---|---|
| `POST /fingerprints/check` | `{"fingerprints": ["…"]}` | `{"existing": ["…"], "missing": ["…"]}` |
| `POST /fingerprints/baseline-diff` | `{"repository": "…", "base_branch": "…", "fingerprints": ["…"]}` | `{"new_fingerprints": ["…"], "pre_existing_fingerprints": ["…"], "base_branch_scanned": true}` |

More than `max_fingerprints_per_request` (50,000) entries → `422
too-many-items` with `"limit": 50000`; the SDK splits larger sets into
several requests and merges the answers (each fingerprint is independent).
An empty list answers the empty result without a query.

### 4.7 `POST /keys` (key renewal)

Empty body. Response `201`, `Cache-Control: no-store`:

```json
{ "api_key": "rda_…", "expires_at": "2026-11-01T00:00:00Z" }
```

`SensorService.RenewAPIKey` as v1: with the multi-key store and a key TTL
the new key is issued **alongside** the presented one, which stays valid
until its own expiry (RFC-014 overlap), so a lost response is recovered by
renewing again with the old key; the orphaned new key expires on its own.
Without a TTL the single inline key is replaced (as v1), so the SDK does not
retry a renewal whose response was lost: a retry with the old key would get
`401`, and it logs the re-enrolment advice instead. Errors: `401`, `403
renewal-refused` (sensor disabled or revoked between authentication and
renewal), `403 scope-denied`, `429`.

### 4.8 Results

Unchanged: [RFC-026](RFC-026-sensor-results-ingest.md) §3 (`PUT
/results/{report_id}`, segments, commit, status, and the
`/commands/{command_id}/results/…` forms).

### 4.9 Problem types

v2 keeps one closed table in `pkg/sensorproto/v2`. The RFC-026 types keep
their URIs (`https://openctem.io/problems/ingest/<name>`, golden-pinned).
Types this RFC adds use `https://openctem.io/problems/sensor/<name>`:

| Status | Type | When | Client retries? |
|---|---|---|---|
| 409 | `sensor/invalid-transition` (ext. `state`) | §4.4 table | No; drop the command when `state` is `canceled`, `expired`, `completed` or `failed` |
| 409 | `sensor/command-claimed` | another sensor won the claim race | No; take the next command |
| 409 | `sensor/transition-conflict` | a replay with a different result or message | No |
| 403 | `sensor/renewal-refused` | §4.7 | No |
| 422 | `sensor/too-many-items` (ext. `limit`) | §4.6 | No; split |

Reused from the RFC-026 table on the new routes: `ingest/unauthenticated`
(401), `ingest/scope-denied` (403), `ingest/command-not-found` (404),
`ingest/invalid-request` (400), `ingest/content-too-large` (413),
`ingest/unsupported-media-type` (415), `ingest/rate-limited` (429),
`ingest/internal` (500), `ingest/unavailable` (503). Details are fixed
templates; they never quote sensor bytes.

### 4.10 Idempotency summary

| Request | Why a retry is safe |
|---|---|
| `GET` routes, `POST /fingerprints/*` | read-only |
| `POST /heartbeat` | last-write-wins snapshot |
| command transitions | same-state replay is `200` without side effects (D5) |
| `PUT …/results/{report_id}` | sensor-chosen id + `Content-Digest` (RFC-026) |
| `POST /keys` | overlap keeps the presented key valid (§4.7); not retried without a TTL |

### 4.11 Evolution rules (how v2 changes without v3)

1. **Additive only** inside v2: new routes, new optional request members, new
   response members, new enum values in sets documented as open (`actions`,
   `features`). Never a new required member, never a changed meaning.
2. **Must-ignore** on both sides for JSON members (D4).
3. **New behaviour is opt-in per feature.** A new capability (leases,
   long-poll `GET /wait`, `GET /config`, signed jobs, scopes) gets a feature
   name; the server lists it in `hello` and the SDK uses it only then. The
   server changes behaviour for a sensor only when that sensor opted in, which
   it does by calling the new route or, for behaviour on an existing route,
   by naming the feature in `OpenCTEM-Sensor-Features` on that request.
4. A breaking change is a new major path (`/api/v3/sensor`) served side by
   side, which this design is meant to avoid.

Reserved for later releases (not built now): command leases
(`lease_expires_at`, lease renewal on the heartbeat), `GET /wait`
long-poll (RFC-023 §9.2a), `GET /config` (`config_version` fetch), runtime
telemetry and validation evidence on v2, RFC 9421 signatures.

## 5. Protocol v1: deprecated, served, measured

### 5.1 Endpoint mapping (v1 → v2)

| v1 | v2 | Change |
|---|---|---|
| `POST /api/v1/agent/heartbeat` | `POST /api/v2/sensor/heartbeat` | doorbell always on; `sensor_id` instead of `agent_id`; disabled → `200 paused` |
| `GET /api/v1/agent/commands?limit=n` | `GET /api/v2/sensor/commands?limit=n` | body is `{"commands": […]}`, not a bare array |
| `POST /api/v1/agent/commands/{id}/acknowledge` | `POST /api/v2/sensor/commands/{id}/claim` | idempotent; `409 command-claimed` on a lost race |
| `POST /api/v1/agent/commands/{id}/start` | `POST /api/v2/sensor/commands/{id}/start` | idempotent |
| `POST /api/v1/agent/commands/{id}/complete` | `POST /api/v2/sensor/commands/{id}/complete` | idempotent; v1 answered a retried complete with 400 |
| `POST /api/v1/agent/commands/{id}/fail` | `POST /api/v2/sensor/commands/{id}/fail` | idempotent |
| `GET /api/v1/agent/suppressions` | `GET /api/v2/sensor/suppressions` | `ETag` / `304` |
| `POST /api/v1/agent/ingest/check` | `POST /api/v2/sensor/fingerprints/check` | 50,000 per request |
| `POST /api/v1/agent/ingest/baseline-diff` | `POST /api/v2/sensor/fingerprints/baseline-diff` | 50,000 per request |
| `POST /api/v1/agent/renew` | `POST /api/v2/sensor/keys` | `201` |
| `POST /api/v1/agent/ingest`, `/ingest/ctis` | `PUT /api/v2/sensor/results/{report_id}` (or `/commands/{id}/results/{report_id}`) | RFC-026: CTIS media type, `Content-Digest`, `202` + status |
| `POST /api/v1/agent/ingest/chunk` | `PUT …/results/{report_id}/segments/{seq}` + `POST …/commit` | complete CTIS per segment |
| `GET /api/v1/agent/ingest/jobs/{id}` | `GET /api/v2/sensor/results/{report_id}` | status resource |
| header `X-Agent-ID` | none | identity from the key |
| header `X-OpenCTEM-Sensor-Features: doorbell, results-v2` | none needed | v2 implies both |

No successor in this release, so **not** deprecated yet: `/ingest/sarif`,
`/ingest/recon`, `/ingest/scan` (successor: SDK-side conversion, or the
user-authenticated import API of RFC-026 WP-A8), `/ingest/scanners`, `/scans`
(scan sessions), `/telemetry-events`, `/credentials/ingest`,
`/api/v1/validation/evidence`.

### 5.2 Deprecation headers

Added by one middleware on the v1 routes of §5.1 only; bodies and status
codes are unchanged, so `protocol_v1_golden_db_test.go` stays green (C1
allows additive headers; RFC-026 §8.3 planned exactly this):

```http
Deprecation: @1790812800
Sunset: Thu, 01 Apr 2027 00:00:00 GMT
Link: </api/v2/sensor/heartbeat>; rel="successor-version"
```

`Deprecation` (RFC 9745) is 2026-10-01T00:00:00Z and `Sunset` (RFC 8594)
2027-04-01, the same dates as the deprecated `/api/v1/agents` management
paths (`legacyv1`), so protocol v1 has one deprecation story. The `Link`
target is the route's successor from §5.1. The SDK logs a one-time warning
when it receives `Deprecation` (it only can if it fell back to v1).

### 5.3 Telemetry

- **Per sensor (stored).** Migration: `sensors.protocol_version smallint`,
  `sensors.protocol_client varchar(256)`, `sensors.protocol_seen_at
  timestamptz`, all nullable. Written by the heartbeat update that already
  runs on every heartbeat (no extra statement): `1` from the v1 heartbeat,
  `2` from the v2 heartbeat; the `User-Agent` is reduced to printable ASCII,
  CR/LF removed, cut at 256 bytes. A sensor on sdk-go 0.8.x (v2 results, v1
  heartbeat) therefore reads `1`: it still needs the upgrade.
- **Shown.** `GET /api/v1/sensors` and `GET /api/v1/sensors/{id}` return
  `"protocol": {"version": 1, "user_agent": "openctem-sdk-go/0.8.1
  (openctemio-sensor/0.4.2)", "seen_at": "…", "deprecated": true}`, or
  `null` before the first heartbeat after the upgrade. `deprecated` is true
  for version 1. The UI shows "Protocol v1 (deprecated): upgrade the sensor".
- **Fleet (metric).** `sensor_protocol_requests_total{protocol, route}`,
  both labels from closed sets (route names, not paths), alongside the
  existing `ingest_v1_requests_total` and `ingest_v2_requests_total`.

### 5.4 Removal

The sunset date is the earliest removal, not an automatic one. v1 routes are
removed (or answer `410` with a problem naming the successor) only in an API
release that ships after 2027-04-01 **and** after the deployment's telemetry
shows no v1 heartbeat for 30 days, or after the operator raises the minimum
sensor protocol (RFC-023 C7/D24; collectors below it keep pushing until
removal). Self-hosted operators decide with their own telemetry.

**Amended 2026-10-05 (owner decision):** protocol v1 was removed ahead of the
sunset date. The live API had served 0 `/api/v1/agent/*` requests (and 3,303
`/api/v2/sensor/*`) in the preceding 24 hours, and every sensor from v0.9.0 on
speaks v2 for the whole surface. Removed: every route under `/api/v1/agent`
(including the ones without a v2 successor: `ingest/sarif`, `ingest/recon`,
`ingest/scan`, `ingest/scanners`, `scans`, `telemetry-events`,
`credentials/ingest`), the `/api/v1/agents` redirects, the v1 heartbeat's
`X-OpenCTEM-Protocol` advert, `pkg/sensorproto/legacyv1` (except the
renamed-environment-variable table), the v1 golden test and the
`compat-v1` CI job. The paths answer 404; a sensor older than v0.9.0 must be
upgraded before the API is.

## 6. SDK behaviour (sdk-go v0.9.0)

### 6.1 Negotiation

`client.Config.Protocol` keeps its values (`SENSOR_PROTOCOL`):

| Value | Behaviour |
|---|---|
| `auto` (default) | `GET /api/v2/sensor/hello` before the first call that needs a protocol (normally the first heartbeat). `200` with `protocol: 2` → feature set F, cached for an hour (a "no v2" answer for 10 minutes). Each call uses v2 if its feature is in F, else v1. `404`/`405` → v1 for everything. When `hello` cannot be answered right now (network, `401`, `5xx`) a control-plane call goes to v1 for this once (v1 is served by every platform and classifies a refused key the same way) and `hello` is asked again on the next call. A v2 call answered `404` without a problem body (server downgraded) goes to v1 and the cache is dropped. |
| `v2` | Results must use v2 (an error otherwise, as since sdk-go 0.8). Control-plane features use v2 when F lists them and v1 otherwise, so a sensor set to `v2` keeps working against api v0.8 (results only on v2). |
| `v1` | Never calls `hello`; every request byte-identical to v0.7.x, `X-Agent-ID` included. |

The v1 heartbeat advert (`X-OpenCTEM-Protocol: 2` after `results-v2`)
remains a trigger to fetch `hello` early. On v2 the SDK sends neither
`X-Agent-ID` nor `X-OpenCTEM-Sensor-Features`.

### 6.2 Public API

No exported identifier is removed, renamed or changes signature
(checked by the gate of §8.6). `Client.PollCommands`, `AcknowledgeCommand`,
`StartCommand`, `CompleteCommand`, `FailCommand`, `SendHeartbeat`,
`SendHeartbeatWithHints`, `CheckFingerprints`, `BaselineDiff`,
`GetSuppressions` and `platform.PlatformClient.RenewKey` route internally.
Additions: `Client.ProtocolFeatures()` (the negotiated F, for logs and
tests), `client.IsCommandGone(err)`, `platform.RenewError`, and the
control-plane vocabulary and problem types in `protov2`. Control-plane errors
unwrap to both `*V2Error` and `*HTTPError`, so `IsAuthenticationError`,
`IsRateLimitError` and `core.AuthFailureStatus` classify them as on v1. A sensor gets protocol
v2 by bumping the module version; no code change.

### 6.3 Behaviour changes a sensor can observe

- A `409 invalid-transition` with `state` canceled/expired, or `409
  command-claimed`, makes the poller drop the command quietly (v1 logged an
  error).
- The heartbeat hints are always present on v2 (the doorbell is implicit).
- Suppressions are revalidated with `If-None-Match`.

### 6.4 Conformance

`pkg/conformance` gains a v2 fake (every route of §4, the transition table,
replays, problems) next to the v1 fake, and runs the SDK against both plus
a "mixed" server (`features: ["results"]`, the api v0.8.0 shape) to prove the
per-feature fallback. The API's `compat-v1` job stays pinned to the last
released SDK; a `compat-v2` job runs the new SDK against the API.

## 7. Sensor (v0.5.0)

Bump to sdk-go v0.9.0. `SENSOR_PROTOCOL=auto|v1|v2` unchanged. Remaining
*agent* wording that refers to the protocol (flags, environment, docs)
becomes *sensor*, with the old names kept as deprecated aliases and a
startup warning (the RFC-023 §9.5 rule: refuse only conflicting values).
CHANGELOG with the migration notice of §10.

## 8. SDK stability: "bump the version and done"

### 8.1 What sensors depend on today

Our sensor (`openctemio/sensor` `main`, sdk-go v0.8.1) imports 17 SDK
packages from 20 non-test files, about 145 distinct exported symbols: `core`
36, `ctis` 33, `platform` 20, `tenable` 10, `scanners` 8, `client` 8, `handler`
5, and 1–4 each from `legacyv1`, `nuclei`, `trivy`, `semgrep`, `betterleaks`,
`strategy`, `subfinder`, `outbox`, `gitenv`, plus `httpsec` in tests. The SDK
exports roughly 1,900 top-level declarations across about 60 packages under
`pkg/`, all of which are public API by Go's rules; nothing is under
`internal/` except `pkg/internal`.

### 8.2 What broke sensors, historically

| SDK change | Kind | Sensor work |
|---|---|---|
| v0.7.0: 19 *Agent* identifiers renamed (codemod `sensor-migrate`) | breaking rename | part of sensor#60 (51 files) |
| v0.8.0: `scanners/gitleaks` → `scanners/betterleaks`, `retry` queue and SQLite `chunk.Storage` removed | breaking package rename + removal | sensor#75 (37 files), #76 (31 files) |
| doorbell (`core.Doorbell`, `SendHeartbeatWithHints`) | new feature, opt-in by wiring | sensor#66 (+305) |
| rejected-key backoff (`AuthGate`) | new feature, opt-in by wiring | sensor#72 (+184) |
| key auto-renew (`platform.KeyRenewManager`) | new feature, opt-in by wiring | sensor#35 (+92) |
| outbox + v2 results | new feature, opt-in by wiring | sensor#76 (+810) |
| parsers for dispatched scans | executor needed explicit registration | sensor#37, #62 |
| release bumps v0.2.0 … v0.8.1 (9 PRs) | the tag | 8 of 9 go.mod/go.sum only (v0.7.2 added 9 lines to `main.go`), because the edits above landed earlier against pseudo-versions |

Two causes, in that order: (1) **features are opt-in by wiring**, because the
runtime (heartbeat loop, poller, outbox, renewal, auth gate) is assembled by
the sensor; (2) **breaking renames in minors**, allowed pre-1.0 and taken
twice in one week. The sensor also builds against pseudo-versions of SDK
`main` between releases (`v0.6.1-0.2026…`, `v0.7.4-0.2026…`), i.e. the two
repos move in lockstep, which hides (2) until a third party upgrades.

### 8.3 A facade that owns the runtime (next release, sdk-go v0.10.0)

New package `github.com/openctemio/sdk-go/sensorkit` (one name a sensor
imports; `pkg/*` stays for advanced use):

```go
s, err := sensorkit.New(sensorkit.Config{ /* zero value = defaults; LoadEnv fills API_URL, API_KEY, SENSOR_* (and migrated AGENT_*) */ },
    sensorkit.WithName(name), sensorkit.WithVersion(Version),
    sensorkit.WithScanners(scanners...), sensorkit.WithCollectors(collectors...),
    sensorkit.WithParsers(parsers...), sensorkit.WithAssetResolver(detectAsset),
    sensorkit.WithScanWorkspace(roots...),
    sensorkit.WithCommandTypes("scan", "collect", "health_check", "validate"),
    sensorkit.WithExecutorMiddleware(validating),
)
if err != nil { return err }
return s.Run(ctx) // negotiation, heartbeat + doorbell, claim/transition, outbox, key renewal, auth backoff, shutdown
```

Everything that is protocol or runtime moves behind `Run`: when the platform
adds the long-poll, leases or signed jobs, the SDK adopts them inside `Run`
and a sensor gets them by bumping the version. Options are functions, so
adding one never breaks a caller; `Config` is one struct whose zero value is
the default, and unknown environment variables and unknown YAML keys are
ignored with a warning.

Our sensor's `runDaemon` today (sensor `main.go:850-1128`, 280 lines, 15 SDK
objects wired by hand):

```go
sensor := core.NewBaseSensor(&core.BaseSensorConfig{...}, pusher)
for _, p := range scannerParsers() { sensor.AddParser(p) }
sensor.SetAssetResolver(...)
// add scanners and collectors, key renewal, doorbell,
// waitForAcceptedKey(ctx, sensor.FirstHeartbeat, sleepCtx),
executor := core.NewDefaultCommandExecutor(pusher)
executor.SetParserRegistry(newParserRegistry()); executor.SetScanTargetPolicy(policy)
executor.SetAssetResolver(...); executor.AddScanner(...) ...
poller := core.NewCommandPoller(apiClient, sensorexec.NewValidatingCommandExecutor(executor, v), &core.CommandPollerConfig{...})
poller.SetDoorbell(doorbell); poller.SetAuthGate(sensor.AuthGate()); go poller.Start(ctx)
sensor.Start(ctx); <-ctx.Done(); keyRenewManager.Stop(); poller.Stop(); sensor.Stop(...); apiClient.Close()
```

After: the `sensorkit.New(...).Run(ctx)` block above plus the sensor's own
code (scanner selection from its config, `detectAsset`, the validating
executor, banners): about 40 lines. `startDaemonKeyRenewal`,
`newDaemonDoorbell`, `waitForAcceptedKey`, `enableOutbox` and most of
`outbox.go` move into the SDK.

### 8.4 Interfaces that can grow

Adding a method to `core.Scanner`, `core.Collector` or `core.Parser` breaks
every implementation. Rules:

1. Plug-in interfaces stay minimal and are **never** extended in place.
2. A new capability is a **new optional interface** that the SDK discovers by
   type assertion (the `io.WriterTo` / `http.Flusher` idiom), e.g.
   `type TargetKinds interface{ TargetKinds() []string }`; absent means the
   old behaviour.
3. Interfaces the SDK *provides* (not implemented by sensors), such as
   `Pusher` or `CommandClient`, are concrete types or sealed with an
   unexported method, so the SDK may add methods to them.
4. Structs passed to plug-ins (`ScanOptions`, `ScanResult`) only gain fields;
   constructors exist for anything with invariants.

### 8.5 `internal/`, semver and v1.0.0

- Move what sensors should not touch under `internal/` (transport details,
  outbox file format, protocol codecs) in v0.10.0–v0.11.0, after the facade
  covers our sensor; every move ships with a `// Deprecated:` forwarder first
  (§8.7).
- Declare **v1.0.0** when (a) our sensor builds on `sensorkit` + plug-in
  interfaces only, (b) the gate of §8.6 has run for two minor releases, and
  (c) the `internal/` moves are done. From then on Go's import-compatibility
  rule applies: a breaking change needs a new module path
  (`github.com/openctemio/sdk-go/v2`), which we commit to avoid; protocol
  changes never require it because the protocol is negotiated (§4.11).
- Until v1.0.0: breaking changes only in a minor release, never in a patch,
  each listed under "Upgrade notes" with the exact edit or a codemod.

### 8.6 CI gates (this release: the first two)

| Gate | Where | Rule |
|---|---|---|
| **API compatibility** | sdk-go CI, every PR | `apidiff` (golang.org/x/exp) between the merge base's latest tag and the PR, per package. Any incompatible change fails unless the PR carries the label `breaking-change` and `CHANGELOG.md` has an "Upgrade notes" entry naming it. |
| **Sensor builds against SDK HEAD** | sdk-go CI, every PR | check out `openctemio/sensor` `main`, `go mod edit -replace` to the PR tree, `go build ./...`, `go vet ./...`, also `-tags platform`. A red build means a sensor would need edits. |
| Sensor nightly against SDK `main` | sensor CI, nightly (next release) | the same in the other direction; opens an issue on failure. |
| Protocol conformance | api CI | `compat-v1` (last released SDK) stays; new `compat-v2` (this release's SDK) on every API PR. |
| SDK bumps automated | sensor `dependabot.yml` (next release) | a separate `openctem` group for `github.com/openctemio/*`, daily, so an SDK release becomes a PR with CI the same day. |

### 8.7 Deprecation policy

- A deprecated exported identifier keeps working for at least **two minor
  releases** (pre-1.0) or until the next major (post-1.0), with a
  `// Deprecated: use X` comment (staticcheck SA1019 flags callers).
- The CHANGELOG of every release has an **"Upgrade notes"** section, empty
  when nothing needs doing; a sensor author reads only that section.
- Settings follow RFC-023 §9.5: old names migrated with a warning, refusal
  only on conflicting values.

### 8.8 Server side: old SDKs keep working

Behaviour changes on an existing route are gated by an opt-in feature (§4.11
rule 3), never by version sniffing of `User-Agent`. The `compat-v1` job runs
the last released SDK against every API build; `compat-v2` will do the same
for v2 once v0.9.0 is the last released SDK.

## 9. Implementation plan

Each step is its own PR, green before the next depends on it.

| # | Repo | PR | Content | Tests | Effort |
|---|---|---|---|---|---|
| 1 | api | this RFC | docs | — | done |
| 2 | api | `feat(sensor): protocol v2 for the whole sensor surface` (api#678) | `pkg/sensorproto/v2`: new paths, problem types (sensor base), hello `features`/limits/deprecations, `Command` and heartbeat DTOs. `handler/sensor_v2_handler.go`: heartbeat, commands poll + 4 transitions, suppressions (ETag), fingerprints check + baseline-diff, keys; calls the existing services. Transition replay logic in `internal/app/command` (one place, used only by v2, v1 behaviour unchanged). Routes in `routes/sensor_v2.go`. Deprecation middleware on the §5.1 v1 routes. Migration: `sensors.protocol_*` columns; heartbeat writes them; Sensors API returns `protocol`. Metric. OpenAPI `api/openapi/sensor-protocol-v2.yaml`. `architecture/sensors.md`. | DB-backed handler tests per route and status (wrong tenant, revoked key, other sensor's command → 404, replays, conflicts, ETag/304, limits); v1 golden unchanged; deprecation headers asserted on every listed v1 route and absent elsewhere; route-authz coverage; `sensorvocab` lint; `check-openapi.sh` | 2–3 days |
| 3 | sdk-go | `feat: protocol v2 for every call` (sdk-go#89) | negotiation (§6.1), v2 codecs, poller handling of the new 409s, suppressions ETag cache, fingerprint splitting, no `X-Agent-ID` on v2; conformance fakes v1 + v2 + mixed; CI: apidiff gate, sensor-compat build | `go test -race ./...`, golangci-lint (whole tree), gofmt, ctis-parity | 2 days |
| 4 | api | `ci: compat-v2 job` | `tests/compat/v2` pinned to sdk-go v0.9.0 once tagged | job green | 0.5 day |
| 5 | sensor | `deps: sdk-go v0.9.0, protocol v2 everywhere` (sensor#80; also names the binary in the User-Agent) | bump, wording, aliases, CHANGELOG + migration notice | build default and `-tags platform`, tests, image smoke | 0.5 day |
| 6 | all | end-to-end proof | scratch API + DB; new sensor: only `/api/v2/sensor/*` in the access log, no `X-Agent-ID`; old sensor v0.4.2: v1 works, gets `Deprecation`, shows `protocol.version = 1` | — | 0.5 day |
| later | sdk-go | v0.10.0 `sensorkit` facade; sensor adopts it; `internal/` moves; v1.0.0 | §8.3–8.5 | sensor-compat gate | 1–2 weeks |

Merge and tag order: api PR (2) → sdk-go PR (3) → tag sdk-go v0.9.0 → sensor
PR (5) → tag api v0.9.0 and sensor v0.5.0 → publish the notice.

## 10. Migration notice (draft, for release notes and third-party authors)

> **OpenCTEM sensor protocol v2 — upgrade by 2027-04-01**
>
> OpenCTEM API v0.9.0 serves the whole sensor protocol under
> `/api/v2/sensor/*`. The old `/api/v1/agent/*` sensor routes keep working
> unchanged but are deprecated: their responses carry `Deprecation` and
> `Sunset: Thu, 01 Apr 2027 00:00:00 GMT` headers, and the Sensors page shows
> every sensor still on protocol v1.
>
> **If you run our sensor:** upgrade to `ghcr.io/openctemio/sensor:v0.5.0`
> (or `go install github.com/openctemio/sensor@v0.5.0`). No configuration
> change. Against an older platform it falls back to v1 by itself.
>
> **If you built a sensor with sdk-go:** bump `github.com/openctemio/sdk-go`
> to `v0.9.0` (`go get github.com/openctemio/sdk-go@v0.9.0`). No code change:
> no exported identifier changed. The SDK asks the platform (`GET
> /api/v2/sensor/hello`) and uses v2 for every feature it offers, v1 for the
> rest. `SENSOR_PROTOCOL=v1` keeps the old requests byte for byte.
>
> **If you call the HTTP API yourself:** move each call per the table in
> RFC-029 §5.1. Identify with the sensor key only (`Authorization: Bearer`
> or `X-API-Key`); drop `X-Agent-ID`. Errors are RFC 9457
> `application/problem+json`; retry only 429/5xx/network errors. Command
> transitions are idempotent: retry a lost `complete` safely. Results are CTIS
> only (RFC-026).
>
> **Check:** the Sensors page shows *Protocol v2* for the sensor, or
> `GET /api/v1/sensors/{id}` returns `"protocol": {"version": 2, …}` after its
> next heartbeat.

## 11. Risks

| Risk | Mitigation |
|---|---|
| A v2 route behaves differently from v1 through duplicated logic | D3: v2 handlers call the v1 services; replay logic lives in the service; tests assert the same DB effects as the v1 golden flow |
| Deprecation headers alter v1 for a picky client | headers only, additive (C1); golden bodies and codes unchanged; proved by `compat-v1` with the last released SDK and by the old sensor image in the e2e run |
| SDK falls back to v1 silently forever (e.g. a proxy blocks `/api/v2`) | `hello` failure is logged once per backoff; the platform shows `protocol.version = 1` for that sensor |
| Idempotent `complete` hides a real double-execution | a replay is accepted only for the same sensor with semantically equal JSON; a different result is `409 transition-conflict`, logged |
| Lost key-renewal response without TTL locks the sensor out | as v1 today; documented; the SDK does not retry it (§4.7); overlap mode (TTL set) is the recommended deployment |
| Heartbeat telemetry write races with other heartbeat columns | written in the same `UpdateHeartbeat` statement |

## 12. Decisions taken and open points

Taken by the owner (2026-10-02): one release moves the whole surface; v1
stays served and deprecated with headers and per-sensor telemetry until old
sensors upgrade; the SDK negotiates and never sends `X-Agent-ID` on v2; a
new sensor release; an implementation-ready spec.

Taken in this RFC (owner may revisit): path names of §4 (`claim` for v1
`acknowledge`, `fingerprints/*`, `keys`); the 2026-10-01 / 2027-04-01 dates
shared with the management-path deprecation; no command `ETag`s and no
leases in this release; the facade in v0.10.0, v1.0.0 after the criteria of
§8.5.

Open for later: leases and long-poll (reserved features), signed requests
(RFC-023 Phase 3), the minimum-protocol lever's UI.
