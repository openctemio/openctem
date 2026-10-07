# RFC-033 — Sensor manifest: register what a sensor is once, heartbeat a digest

> Status: **Accepted** (2026-10-02; owner decisions in §10.2). Proposed
> 2026-10-02 in api#718.
> - Phase 0 (defect fixes) is live: api#714, sdk-go#106, openctemio/ui#589, sensor v0.6.3.
> - Phase 1 is merged: api#718 (migration 000258, live) and sdk-go#108.
> - Phase 2 is designed in §6.12 and in implementation.
> - Config report (§11, research/26 "sensor config doctor" P0, owner
>   decisions F1–F14 adopted as recommended 2026-10-05): API implemented
>   (migration 001061, `PUT /api/v2/sensor/config-report`, heartbeat
>   `config_report` + `send_config_report`, `GET /api/v1/sensors/{id}/config-report`);
>   sdk-go, sensor and web companions built in parallel.
> Scope: api + sdk-go + sensor (`openctemio/sensor`, local checkout `agent`) + ui.
> Builds on [RFC-029](RFC-029-sensor-protocol-v2-and-sdk-stability.md) (protocol
> v2, hello, §4.3.1 sensor-reported capabilities), [RFC-030](RFC-030-scan-work-distribution.md)
> (load report, slots, routing), [RFC-031](RFC-031-managed-sensor-updates.md)
> (content versions) and [RFC-032](RFC-032-sensor-enrollment-and-identity.md)
> (enrollment, approval, request signatures). It does not change who decides
> what a sensor may do: the sensor claims, policy narrows (RFC-029 §4.3.1,
> RFC-032 §6.6).
>
> Owner's question (2026-10-02): "When a sensor first connects to the
> platform, shouldn't it register which capabilities it has? Research deeply
> and give the best design."

## 1. Answer in short

**Yes. The sensor registers a manifest when it connects, and sends it again
only when it changes. Heartbeats carry a digest of the manifest and the
sensor's live load. Nothing that changes slowly is sent every 30 seconds.**

| | Today (RFC-029 §4.3.1) | With the manifest |
|---|---|---|
| When the sensor says what it has | on **every** heartbeat (≈1.9 KB, every 5–60 s) | once on connect (`PUT /api/v2/sensor/manifest`), then on change |
| What a heartbeat carries | identity, load, **and** the whole tool inventory | identity, load and `manifest_digest` (Phase 2 drops the inventory) |
| Which tool serves which capability | lost; only a flat list arrived (§3.2) | each tool lists its `capabilities` (and, Phase 3, `target_types`) |
| Capacity | one number, `max_concurrent_jobs`, which carried the SDK's upper bound 64 (§3.2) | the operator's **ceiling** in the manifest; what the sensor can run **now** (`slots_total`) on every heartbeat, separating what the host has from what it may use |
| What the platform kept | the latest report, overwritten every heartbeat | every **version** of the manifest, with its digest, what was accepted and what was ignored, and the diff as activity events |
| What the sensor learns back | nothing | the digest the platform stored, what it accepted, what it ignored and why (Phase 2: the tools the policy allows, so the sensor refuses the others itself) |
| Sensors that do not send one | — | keep working: the platform derives the manifest from their heartbeat |

The manifest is the one document an administrator reviews when approving a
sensor (RFC-032 E3). Routing reads it to pick the tool that can run a job
(RFC-030), and the activity timeline diffs it.

## 2. Decisions

| # | Decision |
|---|---|
| M1 | **A manifest is the sensor's slow-changing self-description:** build (product, version, commit, SDK), platform (os, arch), resources (CPU cores, memory), concurrency ceiling, sensor-wide capabilities, and its tools with each tool's kind, version, installed state, capabilities, target types (Phase 3) and content versions (RFC-031). Anything that changes every heartbeat stays out: load, slots, queue, outbox, uptime. So do identifying volatiles, as Nomad keeps `unique.*` out of its node class (§4): instance id, hostname, IP. |
| M2 | **`PUT /api/v2/sensor/manifest`** registers it. It is idempotent and keyed by content. The sensor sends it after `hello` and before its first heartbeat, again whenever its own digest changes, and whenever a heartbeat answer asks for it (action `send_manifest`). Feature name `manifest` in hello. |
| M3 | **Digest:** `sha256:` + hex of SHA-256 over the canonical JSON of the manifest as received: objects with sorted keys, no insignificant whitespace, no HTML escaping. The platform computes it and returns it, and the sensor echoes the platform's value in `manifest_digest` on every heartbeat, so the two sides never have to agree on a canonicalization byte for byte. |
| M4 | **The platform is lenient and explicit.** It keeps what is well-formed and known (tool catalog, capability registry, target-type registry), drops the rest, and answers with `accepted` and `ignored` (path + reason). It never rejects a whole manifest for an unknown word, so a newer sensor works with an older platform. Hard limits (size, list lengths) answer 413/422. |
| M5 | **Versions are kept.** `sensor_manifests` stores each distinct manifest per sensor (sanitized document, digest, source, accepted, ignored, first and last seen). `sensors.manifest_digest` points at the current one. The `reported_*` columns that dispatch reads (RFC-029 §4.3.1, migration 000253) become a projection of the current manifest, so no dispatch query changes. |
| M6 | **Change is history.** The diff between two versions is written to the activity timeline with the existing types (`tools_changed`, `version_changed`, `sdk_version_changed`, `capacity_changed`, `content_updated`). Each event carries both digests. No new event category. |
| M7 | **Backward compatible both ways.** For a sensor that sends no manifest (protocol v1, older v2 SDKs), the platform derives one from its heartbeat (`source = heartbeat`), with the same digest, storage and events. A sensor on a platform without the `manifest` feature keeps sending the full heartbeat. Phase 1 keeps the inventory on every heartbeat. Phase 2 drops it only once the platform has acknowledged the digest. |
| M8 | **Capacity is two numbers** (`capacity` vs `allocatable`). The manifest carries the operator's **ceiling** (`SENSOR_MAX_JOBS`; none when unset) and the model (`dynamic`: the SDK sizes slots from CPU, memory and learned tool cost). The heartbeat carries `capacity.slots_total`, what it can run now. Dispatch capacity is the smallest of ceiling, slots and the administrator's limit (§6.1, implemented in Phase 0). |
| M9 | **The sensorkit owns the manifest.** A sensor only registers tools (`ToolRegistry.Register`, `Kit.AddScanner`). The SDK builds the manifest from the registry, the build information and the host, computes the digest, sends it and reacts to `send_manifest`. Platform connection code lives in the SDK (owner principle). |
| M10 | **Defense in depth (Phase 2).** The manifest answer, and a `GET` that re-reads it when `config_version` changes, carry the policy: the tools and capabilities the platform allows this sensor. The SDK refuses (fails with a typed reason) any command for a tool outside it, even if a platform bug dispatched it. |
| M11 | **Routing by tool (Phase 3, RFC-030).** A job needs a capability and a target type. The platform picks a sensor whose effective manifest has a tool that provides both, and names that tool in the command. The flat capability list stays only as the compatibility path. |
| M12 | **Integrity comes from the request.** RFC-032 Phase 1 signs every v2 request (RFC 9421, Ed25519 key bound to the sensor), so the `PUT` that carries a manifest is signed and attributable. No separate document signature is added, and the stored version keeps the key fingerprint that signed it. At enrollment (RFC-032 §6.3) the enroll request carries the first manifest, and approval shows it. |

## 3. Current state (verified 2026-10-02: api `develop` bf003bb9, sdk-go `main` 46525ff, sensor `main` 83db392; live sensor-docker-01: sensor v0.6.1, sdk v0.11.0)

### 3.1 How a sensor says what it has today

- `GET /api/v2/sensor/hello` is a **discovery document only**: limits and
  features. The sensor tells the platform nothing in it.
- **Every heartbeat** (v1 `POST /api/v1/agent/heartbeat`, v2
  `POST /api/v2/sensor/heartbeat`) carries the whole report:
  - `tools[] {name, kind, version, installed, content[]}`
  - a flat `capabilities[]`
  - `max_concurrent_jobs`, `os`, `arch`
  - the build members `sdk`, `sensor`
  - the load report `resources`, `capacity`, `queue`, `running`

  The SDK's tool registry probes tools at most every 10 minutes
  (`DefaultToolProbeTTL`) and sends its cached result on each beat. Measured
  on our scratch run: 1,886 bytes per heartbeat, every 30 s idle and every 5 s
  busy.
- The API sanitizes each heartbeat's report against the tool catalog and
  capability registry (`CapabilityReportInput.Sanitize`), **overwrites**
  `reported_tools`, `reported_capabilities`, `reported_max_jobs`, `reported_os`
  and `reported_arch` (migration 000253), and diffs it against the stored row
  for the activity timeline (`DiffHeartbeat`, migration 000255).
- Dispatch reads the generated `effective_*` columns: the report narrowed by
  the administrator's settings.
- No history of reports is kept. The first-heartbeat tool review (openctemio/ui#583)
  reads whatever the latest heartbeat left.

### 3.2 Defects found while answering (fixed in Phase 0)

| # | Defect (live) | Root cause | Fix |
|---|---|---|---|
| D1 | `reported_max_jobs` 64 next to `reported_capacity.slots_total` 4 on a 4-core sensor; `effective_max_jobs` = LEAST(64, admin 5) = **5**, more than it runs; UI "sensor reports 64 · limit 5". | With no `SENSOR_MAX_JOBS`, sensorkit sizes the poller to `resource.Manager.MaxSlots()`, which is `HardMax` (64) when no cap is set (`pkg/resource/manager.go`). `BaseSensor.withCapabilities` then reported the poller's `MaxJobs()` as `max_concurrent_jobs` (`pkg/core/base_sensor.go:128`). The platform's rule ignored the slots. | sdk-go#106: `max_concurrent_jobs` is only the operator's cap (`Manager.Cap`). api#714: migration 000257, `effective_max_jobs` = the smallest of admin, ceiling and `slots_total`. openctemio/ui#589: "Runs 4 at once now · operator cap 64 · your limit 5". |
| D2 | Every reported tool had `capabilities: null`, `kind: null`; the flat list said `dast`, `sast`, … with no tool behind them. | The registry knew each tool's capabilities (`ToolSpec.Capabilities`), but `core.ToolInfo` had no field for them. The SDK did send `kind` (sdk-go#99), but the API's `HeartbeatTool` and `ReportedTool` had no `kind` either, so ingest dropped it. | sdk-go#106 `ToolInfo.Capabilities`; api#714 parses, sanitizes and stores `kind` and `capabilities` per tool; openctemio/ui#589 shows them on the tool chips and in the first-heartbeat review. |
| D3 | `nuclei` installed with an empty version. | nuclei v3 prints `[INF] Nuclei Engine Version: v3.11.1` only to **stderr**, in ANSI color; `core.CheckBinaryInstalled` read stdout only (`cmd.Output()`), so the parser got "". The ProjectDiscovery recon tools behave the same (`[INF] Current Version:`). | sdk-go#106 `core.VersionOutput` (stdout, else stderr, ANSI stripped, whole text); nuclei parses `Engine Version:`, the recon tools `Current Version:`. |

The three defects share a shape: what the sensor knows about itself loses
structure on the way to the platform (a per-tool mapping flattened, a bound
taken for a capacity, a version on the wrong stream), and nothing on either
side notices. A manifest that the platform validates and **answers**
(accepted / ignored) makes this kind of loss visible on the first connect.

### 3.3 Other facts the design depends on

- `core.Scanner` has no target types (`Name`, `Version`, `Capabilities`,
  `Scan`, `IsInstalled`), so the SDK cannot yet say what a tool scans. Phase 3
  adds an optional interface.
- The doorbell's `actions` field is a closed set that sensors must ignore
  when unknown (`pause`, `resume`, `drain`, `rotate_key`, `update`), so
  `send_manifest` is additive.
- `config_version` already changes when the administrator's tools,
  capabilities or limit change, which is the trigger Phase 2 uses to re-read
  the policy.
- RFC-032 (Accepted): the enroll request carries the sensor's facts and tool
  report, a pending sensor shows its reported tools for approval, and every v2
  request is signed from Phase 1. The manifest is that report, made durable
  and versioned.

## 4. Design principles

| Principle | Taken here |
|---|---|
| Separate what a host *has* (capacity) from what it may *use* now (allocatable); report the second on every heartbeat | M8 |
| Register a full self-description once, then re-register only on change; hash the stable part only, with per-host unique fields excluded | M1, M2, M3 |
| Keep liveness cheap: a minimal heartbeat, and the full state posted only when it changes or after a slow resync interval; the server steers the cadence (the doorbell already does) | M2, heartbeat digest |
| Capabilities are discovered on the host and registered by it, not typed by an admin; a tool is a schedulable resource the host registers | M1 |
| Flat self-declared labels are not enough: versions, per-tool capabilities and content versions need a structured document | M1 |
| The receiver says what it accepted and what it rejected; each side echoes the other's version, not its own canonical form | M3, M4 |
| A periodic resync guards against a lost change: the digest in every heartbeat does this for free | M2 |

The design is therefore a digest in the heartbeat, with a full re-send on a
mismatch. The self-description includes the versions of installed content
(RFC-031), and it is sent on start and on change, rate-limited.

## 5. Trust

A manifest is a **claim** from an untrusted process (RFC-032 §5). It can only
narrow what dispatch does, never widen it. The administrator's limits and the
enrollment token's tool ceiling still apply. The platform sanitizes the
manifest as it sanitizes the heartbeat report today:

- names are checked against the catalog and registry
- lists and sizes are bounded
- versions are reduced to safe tokens
- the document is capped at 256 KiB

What changes is that the claim becomes **durable and attributable**: each
version is stored with when it arrived and, from RFC-032 Phase 1, the key that
signed the request. A sensor that suddenly claims a new tool leaves a version
and an event behind, and the claim is never silently overwritten. Approval
(RFC-032 E3) reviews a specific manifest digest.

## 6. Design

### 6.1 Capacity: ceiling and slots (Phase 0, implemented)

A sensor has two numbers: what it *has* (`capacity`) and what the scheduler
may *use* (`allocatable`):

- **ceiling**: the most jobs the operator lets it run (`SENSOR_MAX_JOBS`,
  `ToolRegistry.SetMaxConcurrentJobs`, `resource.ManagerConfig.Cap`). It is
  static, so it belongs in the manifest (`concurrency.ceiling`), and today in
  `max_concurrent_jobs`. When no ceiling is set nothing is sent. The resource
  manager's `HardMax` (64) is a safety bound, not a capacity.
- **slots**: what it can run now, sized by the SDK from cgroup-aware CPU and
  memory, the tools' learned cost and an AIMD window
  (`resource.Manager.Slots`). It is dynamic, so it goes on every heartbeat
  (`capacity.slots_total`, `slots_free`).

Dispatch capacity (`effective_max_jobs`, migration 000257, and
`Sensor.EffectiveMaxConcurrentJobs`) is the smallest of the administrator's
limit, the ceiling and the slots, among those that are set. Free slots stay
`effective − held`, and no more than a fresh report's `slots_free`
(RFC-030 §5.8.1). The last reported slots keep counting after the report goes
stale (a generated column cannot read the clock), as the last-posted
allocatable value stays in force until the status is next posted. A stale report's
`slots_free` is ignored. A sensor that is gone is excluded by health anyway.

### 6.2 The manifest document

`Content-Type: application/json` (the control-plane media type). Every
member is optional unless noted, and unknown top-level members are ignored and
listed in `ignored`:

```json
{
  "schema": 1,
  "sensor": { "name": "openctemio-sensor", "version": "v0.7.0", "commit": "83db392", "build_time": "2026-10-02T09:00:00Z" },
  "sdk": { "name": "openctem-sdk-go", "version": "v0.13.0" },
  "platform": { "os": "linux", "arch": "amd64" },
  "resources": { "cpu_cores": 4, "mem_total_bytes": 8589934592 },
  "concurrency": { "ceiling": 0, "model": "dynamic" },
  "capabilities": ["validate"],
  "tools": [
    {
      "name": "nuclei", "kind": "scanner", "version": "v3.11.1", "installed": true,
      "capabilities": ["dast", "validate:nuclei"],
      "target_types": ["url", "host"],
      "content": [ { "name": "nuclei-templates", "version": "v10.4.9", "digest": "sha256:…", "managed": true } ]
    }
  ]
}
```

| Member | Meaning | Limits |
|---|---|---|
| `schema` (required) | Document version, `1`. Any other value is answered 422 `manifest-schema-unsupported`. | — |
| `sensor`, `sdk` | Build, as the heartbeat's build members today. | strings ≤ 128 |
| `platform` | `os`, `arch` (runtime.GOOS/GOARCH). | ≤ 32 each |
| `resources` | What the sensor may use: cgroup CPU quota in cores and the memory limit. These are display and selection inputs, not capacity. | clamped like the load report |
| `concurrency` | `ceiling`: the operator's cap, 0 when none. `model`: `dynamic` (slots from resources) or `fixed` (`ceiling` is the slot count). | 0..100 |
| `capabilities` | **Sensor-wide** capabilities: those served whatever the tools (`validate`). A tool's own capabilities go on the tool. | ≤ 64 |
| `tools[]` | One entry per registered tool: `name` (catalog name, required), `kind` (`scanner`, `collector`), `version`, `installed`, `capabilities` (what it serves besides its name), `target_types` (Phase 3), `content[]` (RFC-031: `name`, `version`, `digest`, `source`, `managed`; **no timestamps**, which stay on the heartbeat). | ≤ 64 tools, ≤ 32 capabilities and ≤ 16 target types per tool |

The flat capability list that dispatch reads today is derived from the
manifest as the union of the installed tools' names, the installed tools'
capabilities and the sensor-wide capabilities. This is the same rule as the
SDK's `ToolRegistry.CapabilityReport`.

### 6.3 Digest

`manifest_digest = "sha256:" + hex(SHA-256(canonical(manifest)))`. Here
`canonical` re-encodes the JSON value with object keys sorted, no
insignificant whitespace and no HTML escaping. It is the RFC 8785 subset that
matters for a document with only strings, booleans, small integers, arrays
and objects.

The platform computes the digest over the manifest **as received**, so the
digest also changes for members it ignores. It returns the digest, and the
sensor echoes that value. The sensor computes its own digest the same way, but
only to notice local changes; a mismatch with the platform's value can never
loop (M3).

Timestamps, hostnames, instance ids and the load are not in the document, so
the digest changes only when the sensor's capabilities, build or ceiling
change. Content versions are in it on purpose: a new template release is a
change worth a version (RFC-031).

### 6.4 Wire

**Hello.** The platform lists `manifest` in `features` when it serves this
RFC. A sensor that does not see it keeps the heartbeat-only behaviour.

**`PUT /api/v2/sensor/manifest`** is authenticated with the sensor key (RFC
9421 signature from RFC-032 Phase 1), takes the per-sensor control-plane write
budget, and accepts at most 256 KiB.

```http
PUT /api/v2/sensor/manifest
Content-Type: application/json

200 OK
{
  "manifest_digest": "sha256:9f…",
  "changed": true,
  "accepted": { "tools": ["nuclei", "semgrep"], "capabilities": ["dast", "nuclei", "sast", "semgrep", "validate", "validate:nuclei"] },
  "ignored": [ { "path": "tools[2]", "value": "zap", "reason": "unknown-tool" },
               { "path": "tools[0].capabilities[3]", "value": "xss-v2", "reason": "unknown-capability" } ]
}
```

- `changed` is false when the digest equals the current version. In that case
  nothing is written beyond `last_seen_at` of the version.
- Errors use RFC 9457 problems: 413 `content-too-large`, 422
  `manifest-invalid` (not a JSON object, no `schema`, or a member of the
  wrong type), 422 `manifest-schema-unsupported`, 503 `unavailable` (the tool
  catalog could not be read; retry), 403 `scope-denied` (the sensor was
  disabled in the meantime).
- **Phase 2 adds `policy`** to the answer: `{allowed_tools, allowed_capabilities,
  max_jobs, config_version}`. These are the effective values after the
  administrator's narrowing. `GET /api/v2/sensor/manifest` returns the same
  answer for the stored version and policy, and the sensor calls it when the
  heartbeat's `config_version` changes.

**Heartbeat.** A new optional member `manifest_digest`:

- When it differs from the stored current digest, or nothing is stored, the
  doorbell answer adds the action **`send_manifest`**. Sensors ignore unknown
  actions, so this is safe for every deployed SDK.
- Phase 1: the SDK still sends its inventory on every heartbeat, as today.
- Phase 2: once a `PUT` has been answered for the current digest, the SDK
  omits `tools`, `capabilities` and `max_concurrent_jobs` from heartbeats.
  The platform then keeps the manifest's values, and an absent list already
  means "not reported, keep the stored value".

### 6.5 Processing (platform)

1. Decode leniently, check `schema`, compute the digest.
2. Sanitize with the same catalog lookup as the heartbeat
   (`KnownCapabilityNames`): tools against the tool catalog, capabilities
   against the registry (plus tool names, `validate`, `validate:<known tool>`),
   target types against the asset-type registry (Phase 3). Kinds come from a
   closed set. Each drop goes into `ignored`.
3. If the digest equals `sensors.manifest_digest`, touch the version's
   `last_seen_at` and answer `changed: false`.
4. Otherwise, in one transaction:
   - insert the version into `sensor_manifests`
   - point `sensors.manifest_digest`, `manifest_at` and `manifest_source` at it
   - write the projection into the `reported_*` columns (tools with kind and
     capabilities, flat capabilities, ceiling, os, arch, `reported_at`)

   Then diff against the previous projection with `DiffHeartbeat` (tools,
   capacity, content) and record the events with both digests. Events are
   best-effort, as for heartbeats.
5. Keep the last 50 versions per sensor, and any version seen in the last
   90 days. The rest are pruned in the same transaction that stores a new
   version.

### 6.6 Derived manifests (sensors without one)

A heartbeat without `manifest_digest` that carries a capability report is
turned into a manifest by the platform. The tools, flat capabilities, ceiling
and os/arch come from the report. The build comes from the sdk and sensor
members or the User-Agent. Sensor-wide capabilities are the flat ones that no
installed tool provides.

The platform digests the derived manifest the same way and stores a version
with `source = heartbeat` only when the digest changes. Every sensor therefore
gets versioned history and the same events from day one, and the heartbeat
path writes nothing extra while nothing changes: the comparison uses the
digest already in the row the heartbeat reads.

A sensor on an SDK from before per-tool capabilities (sdk-go < v0.13) sends
only the flat list. Its derived manifest therefore lists `dast`, `sast` and
the like as sensor-wide, because no tool claims them. This is honest: the
mapping was never sent.

When a sensor later sends a real manifest, that is a new version with
`source = sensor`, because its digest differs. From then on its heartbeat
digest governs, and the platform stops deriving manifests for it.

### 6.7 Policy back to the sensor (Phase 2)

The answer to `PUT` and `GET /api/v2/sensor/manifest` carries the effective
policy. The SDK keeps it, and its command poller fails, with the typed reason
`tool-not-allowed`, any command whose tool or required capability is outside
`allowed_tools` / `allowed_capabilities`. This is a second line behind the
platform's own gates (zone predicate, tool gate, capability gate). It costs
one comparison per command and turns a platform-side dispatch bug into a
visible failure, where today the sensor would run a tool the administrator
disallowed. A sensor whose policy is older than the heartbeat's
`config_version` re-reads it before it claims again.

### 6.12 Phase 2 as decided (O1–O4)

**Policy echo (O2).**

- Both the `PUT /api/v2/sensor/manifest` answer and a new
  `GET /api/v2/sensor/manifest` carry:
  - `policy: {allowed_tools, allowed_capabilities, max_jobs}`: the sensor's
    effective tools, capabilities and capacity, so the administrator's
    narrowing is already applied.
  - `heartbeat: {omit_inventory}`: see "Slim heartbeat" below.
- `GET` answers for the stored current manifest, or 404 `manifest-not-found`
  when there is none (the sensor then PUTs).
- The SDK keeps the policy and re-reads it with `GET` on the first heartbeat
  whose `config_version` differs from the one it read the policy under. The
  administrator changing tools, capabilities or the limit already changes
  `config_version`.

**Refusal on the sensor (O2).** A command names a tool when its payload has
`scanner`, or else `preferred_tool`. This is the same rule as the platform's
tool gate (`commandToolSQL`), and the name goes through
`CanonicalScannerName`. If a policy is known and the tool is not in
`allowed_tools`, the SDK claims and starts the command, then reports it
**failed** with `tool-not-allowed: <tool> is not allowed on this sensor by the
platform's policy`. It never runs it. A command that names no tool (a
validation, a collection) and a sensor that has no policy yet are not gated.
Before refusing, the SDK re-reads a policy that is stale (a newer
`config_version` was announced). The heartbeat that announces the
administrator's change also rings the doorbell for the command the change
allowed, so without the re-read that command would be refused.
The failure is visible on the job and in the activity timeline. Silently
leaving the command pending would hide the platform bug that dispatched it.

**Slim heartbeat (O3).**

- After an answer with `omit_inventory: true`, and while the heartbeat
  echoes the acknowledged digest, the SDK leaves `tools`, `capabilities`
  and `max_concurrent_jobs` out of the heartbeat. An absent list already
  means "keep the stored value" (migration 000253), so the platform keeps the
  manifest's projection.
- What still changes between manifests is each piece of content's freshness:
  `checked_at`, `fetched_at`, the last refresh `error` (RFC-031 health). This
  goes in a compact `content` member, `[{tool, name, version, updated_at,
  fetched_at, checked_at, source, digest, managed, error}]`. The platform
  merges it into the stored tools' content, so `content_stale` and
  `content_refresh_failed` keep working.
- A tool installed or removed, or a version or content version that changed,
  is a manifest change. It reaches the platform as a new `PUT`, not as a
  heartbeat.
- **Kill switch:** `SENSOR_SLIM_HEARTBEAT=false` on the platform (default
  `true`). Answers then say `omit_inventory: false`, and a heartbeat that
  arrives slim gets `send_manifest`. The sensor re-registers, reads
  `omit_inventory: false` and goes back to full heartbeats within one
  interval.
- A platform from before Phase 2 never says `omit_inventory: true`, so a newer
  SDK never slims against it.
- **Savings.** Measured on the official sensor, a slim heartbeat is about
  2.1 KB against 2.6 KB for a full one, roughly 20 %. The load report
  (resources, per-tool cost, queue) is most of a heartbeat, and it stays.

**Re-approval (O1).** None. When a registered manifest replaces the previous
one, the platform records one **`manifest_changed`** event (category
`updates`) with the diff:

- tools added and removed
- version changes
- per-tool capabilities added and removed
- sensor-wide capabilities
- ceiling, platform and build

Both digests go in its details. Content versions keep their own
`content_updated` events. A heartbeat that carries `manifest_digest` writes no
`tools_changed` or `capacity_changed`: for a registering sensor the manifest
records those. What a new tool may do is still decided by the sensor grant
(RFC-052): a tool outside the grant is refused at admission. (The tool limit
on the sensor, `sensors.tools`, is gone since migration 001149.) Manifests derived from heartbeats keep the heartbeat's
`tools_changed` and `capacity_changed` events (§6.6), so nothing is recorded
twice.

**Resources (O4).** `resources` (CPU cores, memory) are part of the manifest
read with `sensors:read`, as hostname and IP are.

**UI.** The sensor drawer's "Manifest" section shows:

- the current digest, its source and since when
- resources, ceiling and model
- tools with kind, version, installed state, capabilities and content
  versions
- sensor-wide capabilities and ignored items
- the version history, with a diff of each version against the one before it

The Activity timeline renders `manifest_changed` with its diff.

### 6.8 Routing by tool and target type (Phase 3, with RFC-030)

- A tool declares the target types it scans through an optional SDK
  interface, `core.TargetTyper`; scanners that do not implement it declare
  none. For example:
  - nuclei → `url`, `host`, `ip`, `domain`
  - trivy → `repository`, `container_image`, `filesystem`
  - semgrep and betterleaks → `repository`, `filesystem`
- A scan's work item already knows its target type. Selection (RFC-030 §5.3)
  takes the sensors with an effective tool that serves the required
  capability **and** the target type, prefers the tool the scan named, and
  writes the chosen tool into the command.
- This retires the last use of the flat capability list for routing. The flat
  list stays for older sensors.

### 6.9 Enrollment and approval (Phase 4, with RFC-032)

- The enroll request (`POST /api/v2/sensor/enroll`, RFC-032 §6.3) carries the
  first manifest. The pending-approval view shows it: tools with versions and
  capabilities, content, build, platform, resources, ceiling, and any ignored
  items.
- Approval records the manifest digest it saw. The approval audit entry
  names that digest.
- A later manifest that **adds** a tool does not widen anything by itself,
  because the token's tool ceiling and the administrator's limits still
  narrow it. It is shown as "installed but not allowed" (openctemio/ui#583 already
  does) and raises a `tools_changed` event. Whether it should also need
  re-approval is owner decision O1.

### 6.10 SDK and sensor

`sensorkit` and `core.BaseSensor` own all of it. A sensor registers tools and
nothing else.

- `core.Manifest` is built by `BuildManifest` from the capability report, the
  build information, `HostOS`/`HostArch`, the resource prober and the ceiling.
  `Manifest.Digest()` computes the local digest.
- `client.PutManifest` is the v2 call, used only when `hello` lists
  `manifest`.
- `BaseSensor`:
  - sends the manifest before the first heartbeat
  - recomputes the digest on each heartbeat (the registry already caches
    probes for 10 minutes, so this is a hash over a few hundred bytes)
  - re-sends when the local digest changes or a heartbeat answer asks
    (`send_manifest`)
  - echoes the platform's digest in `manifest_digest`
  - backs off on failure and never blocks heartbeats: a failed `PUT` is
    retried on the next heartbeat
- The official sensor gets all of this from the SDK bump. Its per-scanner
  capabilities (`validate:nuclei`, `container` for trivy-image) are already
  registered per tool (sensor#99).

### 6.11 UI

- Sensor drawer:
  - "Tools & capacity" shows each tool's capabilities (openctemio/ui#589) and, from
    Phase 3, its target types.
  - A new "Manifest" section shows the current digest (short), source
    (sensor / derived), received time, the ignored items, and the version
    history with a diff between two versions.
- The first-heartbeat review (openctemio/ui#583) becomes the manifest review: it reads
  the current manifest, so it works the same before the first heartbeat when
  the sensor registered first.
- Approval (RFC-032 Phase 2) shows the manifest and records its digest.

## 7. Compatibility

| Sensor ↓ / platform → | Without `manifest` (today) | With `manifest` |
|---|---|---|
| v1, or v2 SDK before the manifest | unchanged | unchanged on the wire. The platform derives manifests from heartbeats (§6.6), with versions and events. |
| SDK with the manifest | does not see `manifest` in hello and keeps the full heartbeat (today's behaviour) | registers, echoes the digest. Phase 1: still a full heartbeat. Phase 2: slim heartbeat after the digest is acknowledged. |

- The v1 wire is unchanged (`protocol_v1_golden_db_test.go`).
- `send_manifest` goes only to sensors that sent a `manifest_digest`, so older
  sensors never see it.
- Phase 2 slimming is safe because an absent list already means "keep the
  stored value" (migration 000253 semantics).
- Migrations are additive: a new table, nullable columns and a generated
  column change (000257) with a down migration.

## 8. Phased plan

| Phase | Scope | Effort | Risk |
|---|---|---|---|
| **P0** (done, in review) | D1–D3 fixes (§3.2): ceiling vs slots in SDK and API, per-tool kind and capabilities end to end, nuclei and recon version parsing, UI wording and chips. api#714, sdk-go#106, openctemio/ui#589, sensor#99. | S (done) | low |
| **P1** | API: migration (`sensor_manifests`, `sensors.manifest_digest`, `manifest_at`, `manifest_source`), `PUT /api/v2/sensor/manifest` with `accepted`/`ignored`, `manifest` feature, heartbeat `manifest_digest` + `send_manifest`, derived manifests, version-diff events, management reads `GET /api/v1/sensors/{id}/manifest` and `/manifests`. SDK: `core.Manifest`, `BuildManifest`, digest, `client.PutManifest`, `BaseSensor` register / echo / re-send. Sensor: SDK bump. Docs. | M (api ≈ 3 d, sdk ≈ 2 d) | low: additive, the heartbeat stays full |
| **P2** | §6.12: slim heartbeat after acknowledgement with a `content` freshness block, `policy` + `heartbeat.omit_inventory` in the answer + `GET /api/v2/sensor/manifest`, SDK refuses disallowed tools (`tool-not-allowed`), `manifest_changed` event, UI manifest section with history diff. | M | medium: slimming must be exact, so it is gated on `omit_inventory` acknowledged per sensor and kill-switchable (`SENSOR_SLIM_HEARTBEAT`) |
| **P3** | `core.TargetTyper` + target types for the bundled scanners; target-type registry check; RFC-030 selection by capability × target type with the chosen tool written into the command. | M–L | medium: routing change, behind the RFC-030 rollout |
| **P4** | RFC-032 tie: manifest in the enroll request, approval shows it and records its digest; signing key fingerprint stored per version; re-approval policy per O1. | S on top of RFC-032 P1/P2 | low |

### 8.1 Phase 1 tracking

| Part | State |
|---|---|
| api: migration 000258 (`sensor_manifests`, `sensors.manifest_*`), `PUT /api/v2/sensor/manifest`, feature `manifest`, heartbeat `manifest_digest` + `send_manifest`, derived manifests, version-diff events with digests, `GET /api/v1/sensors/{id}/manifest[s]`, `manifest_digest/at/source` on the sensor response | implemented with this RFC (DB tests `sensor_manifest_db_test.go`, unit tests `manifest_test.go`) |
| sdk-go: `core.Manifest`, `BuildManifest`, `client.PutManifest`, `BaseSensor` register / echo / re-send, conformance fake | sdk-go#108 (merged; the digest is pinned to the same value by a test on both sides) |
| sensor | SDK bump only. Verified end to end: a sensor built with the SDK branch registered against this API (`source = sensor`, ceiling 0, model dynamic, 4 tools); a second version followed when its content manager installed nuclei templates and the trivy DB |
| ui | Phase 2 (manifest section) |

Phase 0 and Phase 1 are live (2026-10-02): sensor v0.6.3 shows nuclei
v3.11.1 with per-tool capabilities, effective capacity is 4, and a
heartbeat-derived manifest exists for sensor-docker-01.

## 9. Alternatives considered

- **Keep the full report on every heartbeat.** This is today's design. It
  costs ~1.9 KB × every beat × every sensor and overwrites history. It also
  lost structure (D2) with nobody noticing, because nothing answers.
  Rejected.
- **Send the manifest only once, at enrollment.** Tools are installed and
  upgraded, and content changes daily. A one-time registration goes stale.
  Rejected.
- **Let the platform poll the sensor for its manifest.** Sensors are
  outbound-only (RFC-023), so there is nothing for the platform to poll.
  Rejected.
- **A manifest signed as a detached JWS.** RFC-032 Phase 1 signs every request
  with the sensor's bound key, which already covers the `PUT`. A second
  signature format adds key handling for no new guarantee. Rejected; we
  revisit it if manifests are ever relayed through a third party.
- **Digest computed only by the sensor.** Two code bases would then have to
  agree on canonical bytes forever, and any drift would cause re-send loops.
  The platform computes the digest and the sensor echoes it.
  Chosen instead.
- **Free-form labels instead of a structured
  manifest.** Labels cannot carry versions, per-tool capabilities or content.
  They can come later as an optional `labels` member if operators need
  free-form routing hints.

## 10. Decisions

### 10.1 Technical decisions taken (no owner input needed)

M1–M9 and M12 (§2) are protocol and implementation choices inside the model
the owner already accepted in RFC-029 §4.3.1 and RFC-032 §6.6: the sensor
claims, policy narrows. They change no permission, no data-scope rule and no
user-visible policy. Phase 1 implements M1–M9 except the parts marked
Phase 2+.

Also decided here:

- History is kept for 50 versions or 90 days, whichever keeps more.
- The manifest is readable with `sensors:read`, like today's reported tools.
- `send_manifest` is a new doorbell action, sent only to sensors that send a
  digest.
- `ignored` items are visible to administrators in the API and, from Phase 2,
  in the UI.

### 10.2 Owner decisions (2026-10-02)

The owner accepted each recommendation below as written. §6.12 is the
resulting Phase 2 design.

| # | Decision |
|---|---|
| O1 | **No re-approval** when a manifest adds a tool or changes its build. The change is recorded as an event (`manifest_changed`), and the sensor grant still governs what the tool may do. |
| O2 | **The SDK refuses** commands for tools outside the platform's policy. The platform returns the policy (allowed tools, capabilities, capacity) in the manifest answer and on `GET /api/v2/sensor/manifest`. |
| O3 | **Slim heartbeats.** Once the manifest is acknowledged, heartbeats drop the tool list. This is per sensor and has a server kill switch (`SENSOR_SLIM_HEARTBEAT`). |
| O4 | **Resources** (CPU, memory) from the manifest are visible to `sensors:read`. |

The questions as they were put, with the recommendation:

| # | Question | Recommendation |
|---|---|---|
| O1 | When an **approved** sensor's manifest adds a tool, or changes its build, should the sensor need **re-approval** before it receives jobs for it? | **No re-approval.** Narrowing already prevents widening: the token's tool ceiling and the admin's tool list still apply, and a new tool outside them shows as "installed but not allowed" with one-click Allow. Record a `tools_changed` event, and offer an optional tenant setting "notify me when a sensor's tools change". Re-approval on every template release or version bump would train admins to click through. |
| O2 | Should the SDK **refuse** commands for tools outside the platform's policy (M10), turning a platform-side dispatch bug into a failed job rather than a run? | **Yes**, in Phase 2. It is cheap and visible, and it matches RFC-023's "enforced on the sensor too" principle. The failure carries the typed reason, so it is not a silent drop. |
| O3 | **Slim heartbeats** (Phase 2): drop the inventory from heartbeats once the manifest is acknowledged? It saves the inventory's bytes (measured later: about 20 % of a heartbeat). | **Yes**, gated per sensor on an answer that says so (a platform from before Phase 2 never does), with a server kill switch. |
| O4 | Should the manifest's `resources` (cores, memory) be **shown to tenant users** with `sensors:read`, or only to administrators? It is host sizing information, comparable to the hostname and IP already shown. | Show to `sensors:read`, as hostname and IP are today. |

## 11. Config report (research/26 P0)

The manifest says what a sensor *is*. The config report says whether it is
*set up correctly*: the results of preflight checks the sensor runs on itself
(state volume, key renewal, tools, TLS trust, proxy inheritance, local policy,
settings it does not know) that used to reach only its stderr. It is a
separate document from the manifest because check results change more often
than the manifest (owner decision F2).

**Wire.**
- Hello feature `config_report` (`protov2.FeatureConfigReport`). A sensor sends
  nothing new to a platform that does not list it.
- `PUT /api/v2/sensor/config-report` (`protov2.ConfigReportPath`), sensor-key
  authenticated like `PUT /manifest`, on the per-sensor control-write budget.
  JSON, at most 65536 bytes (`protov2.MaxConfigReportBytes`; 413
  `content-too-large` with the limit). Not JSON or nested deeper than 6: 400
  `invalid-request`. Schema other than 1 or no `checks` array: 422
  `config-report-invalid`. Inactive sensor: 403 `scope-denied`. The answer is
  `{config_report_digest, changed, ignored[]}`.
- Heartbeat member `config_report: {digest, health, fail, warn, observed_at}`
  (v2 and v1 bodies). The heartbeat UPDATE stores the echoed digest in
  `sensors.config_heartbeat_digest` (NULL when absent). The v2 answer carries
  the action `send_config_report` when the digest is non-empty and differs
  from the stored one.
- Document (schema 1): `observed_at`, `trigger` (start, change, requested),
  `runtime.kind`, the sensor's `config_health`, `checks[]` (id, status,
  severity, code, typed `params`, `keys`, `summary`, `excerpt`, `blocks`),
  `settings[]` (name, set, source, secret, valid) and `truncated`.

**Limits and sanitizing** (`pkg/domain/sensor/config_report.go`,
`SanitizeConfigReport`). Every rule is enforced by the platform, whatever the
SDK did:
- closed sets for status, severity, trigger, runtime kind, setting source and
  blocks; id and code by pattern; an invalid status or id drops the check;
- `params` typed and re-validated: exactly one of int (|n| ≤ 1e12), bool,
  enum, path (absolute, ≤ 256 bytes, no control or bidi characters, no `..`
  segment), host (name or IP; no scheme, user info or port), version, name,
  names (≤ 8); anything else is dropped and its value never echoed;
- `summary` ≤ 300 runes and `excerpt` ≤ 512 bytes, control and bidi
  characters replaced; stored as data;
- at most 200 checks (unique by id and canonical params), 300 settings, 16
  params, 8 keys, 8 blocks; the rest is listed in `ignored` as one `limit`
  item;
- a settings entry keeps only name, set, source, secret and valid. Any other
  member, `value` above all, is dropped unread and never stored or echoed;
- unknown members anywhere are dropped and listed (`unknown-member`), never
  an error.

The platform computes its own digest ("sha256:" + hex over the canonical JSON
of the sanitized report with `observed_at` emptied, so re-running the same
checks does not change it) and its own health; it never trusts the sensor's
`config_health`.

**Storage** (migration 001061). `sensor_config_reports` keeps the latest
report per sensor (primary key `sensor_id`, `tenant_id NOT NULL`, digest,
health, fail/warn counts, `report jsonb`, `observed_at`, `received_at`).
`sensors.config_report_digest` and `config_health` point at it. The same
digest only moves `received_at`. Every read and write is tenant-scoped.

**Health.** The rollup over the sanitized checks: `blocked` when a `fail`
blocks `role:*`, `impaired` on any other fail or error, `attention` on a warn
of severity warning or critical, `ok` otherwise. `AssessHealth` gains
`config_check_failed` (critical), `config_check_warning` (warning) and
`config_report_stale` (warning: the latest heartbeat echoed another digest or
none, while the sensor is online). A stale report never raises the failed or
warning reasons. The fleet `degraded` state works unchanged, and the sensor
list and detail carry `config_health`.

**Explanations come from the platform.** Titles, the "why" text and fix
snippets (env, compose, helm) come only from the catalog in
`internal/app/sensor/config_check_catalog.go`, keyed by check id and code
(owner decision F12). Parameters go into the why as plain text and into the
snippets escaped per format: shell-quoted for env (a value with a control
character drops the env snippet), YAML-quoted for compose and helm. A drift
test fails when a contract id or code has no entry. A check id the catalog
does not know (a newer sensor) is shown with `known: false`, its id as the
title, and no why or fix.

**Management read.** `GET /api/v1/sensors/{id}/config-report`
(`sensors:read`, tenant-scoped, 404 for another tenant's sensor) returns
`state` (reported, derived, none), `stale`, `health`, times, `runtime_kind`,
counts, the explained checks (sorted fail, error, warn, skip, pass, then
group, then id) and the declared settings. A sensor that sends no report gets
a checklist derived from its heartbeat: each reported tool's install state
(`tool.<name>.binary`), `tools.available` and `policy.local`, with a
`derived_note` asking for an upgrade.

**What a report cannot do.** It only informs: P0 changes no dispatch (that
is P1, owner decision F7), adds no route on the sensor, and carries no
secret values.

**Threat model** (research/26 §4.9):

| # | Threat | Control |
|---|---|---|
| T1 | A compromised sensor phishes the administrator with "fix" text | Fixes and wording come only from the platform catalog; sensor text is data, rendered as text; params are typed and escaped per format |
| T2 | A compromised sensor stores junk or script through the report | 64 KiB cap, depth 6, closed sets, typed params, bounded stripped text, per-sensor write budget, one row per sensor, digest dedup |
| T4 | A sensor makes the platform persist a secret | Settings entries are reduced to name/set/source/secret/valid; a `value` is dropped unread and never echoed (canary tests on the stored row and the read) |
| T8 | Another tenant reads a sensor's report | `tenant_id NOT NULL`, every query tenant-scoped, 404 cross-tenant (BOLA tests) |
| T9 | A network attacker forges a report | The same authenticated channel as the heartbeat |

Tests: `config_report_test.go` (sanitizing, digest, rollup, stale rule,
derived checklist), `config_check_catalog_test.go` (contract drift, escaping),
`sensor_config_report_db_test.go` in `internal/infra/postgres` (tenant
scoping, migration up/down/up) and `internal/infra/http/routes` (wire,
dedup, heartbeat action, management read, isolation).

## 12. Tool contracts in the manifest

Tools ported to the tool contract (sdk-go `docs/rfcs/sensor-sdk-v2.md`) add
`contract: {api_version, digest, version, class, tier, network, consumes,
produces}` to their `tools[]` entry. The platform validates it whole, stores
it inside the manifest version (per sensor, per tenant, content-addressed by
the manifest digest; no cross-tenant table), diffs it, shows it on the
Manifest tab and uses `produces` to narrow the output-type binding of the
tool's command-bound reports (it can only narrow). Sensors without contracts
are unchanged. Details: [architecture/sensors.md](../architecture/sensors.md#tool-contracts),
[architecture/scan-stages.md §4](../architecture/scan-stages.md#4-report-output-type-binding-owner-decision-g12).

## 13. Sources

- RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- RFC 9457, Problem Details for HTTP APIs: https://www.rfc-editor.org/rfc/rfc9457
