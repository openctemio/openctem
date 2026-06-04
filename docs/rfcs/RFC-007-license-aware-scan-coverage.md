# RFC-007: License-Aware Continuous Scan Coverage (Tenable Nessus Pro + Tenable.sc)

- **Status**: Proposed
- **Created**: 2026-06-04
- **Owner**: Platform / Discovery
- **Problem**: A customer must continuously cover a large estate (e.g. **3000 IPs**) with vulnerability scanning, but their scanner license is smaller than the estate (e.g. **500 active IPs**). They want to scan in rolling, license-sized batches, store every result durably in OpenCTEM, free the scanner per cycle, and loop until the whole estate is covered — **without** wrongly resolving findings for the assets that weren't in the current batch. The customer runs **both Nessus Professional (unlimited IPs) and Tenable.sc (active-IP licensed)** and needs *both* supported as first-class engines.

---

## 0. Two engines, two license models — both first-class

| Engine | License unit | Reclaim | Role in this design |
|---|---|---|---|
| **Nessus Professional/Expert** | Per *scanner*, **unlimited IPs** | n/a | Breadth engine. Batching is for **scan duration/load**, not license. No reclaim step. |
| **Tenable.sc / SecurityCenter** | **Active IPs** in repositories (e.g. 500) | **Explicit removal** of repo results (immediate) and/or **aging** (passive) | License-capped engine. Scheduler enforces the cap; reclaim frees slots each cycle. Managed scanners reach segmented networks Nessus Pro can't. |
| *(ref) Tenable.io / VM* | Assets, **90-day** count | Deletion lag ~90d | **Not** the customer's case; rotation can't reclaim in time. Out of scope, noted so the model isn't mis-applied. |

**Design stance:** a single engine-agnostic abstraction (`ScanEngine`) with a per-engine **`LicensePolicy`**. The scheduler is identical for both; it reads the policy to decide batch sizing and whether a reclaim step runs:

- `nessus_pro` → `LicensePolicy{Mode: Unlimited, Reclaim: None}` → batch = perf chunk, no reclaim.
- `tenable_sc` → `LicensePolicy{Mode: ActiveIPCap, Cap: 500, Reclaim: Remove}` → batch ≤ headroom, reclaim after each cycle.

This makes the customer's "scan 500 → store → free 500 → next 500" loop a **safe, first-class** mode on `.sc`, while on Nessus Pro the same coverage is achieved without the fragile delete loop.

## 1. Current state (grounded — more exists than expected)

Reusable building blocks already in the codebase:

- **Scan domain** (`pkg/domain/scan`, `internal/app/scan`): `Scan` entity with `Targets`/`AssetGroupIDs`, **`TargetsPerJob`** (batch size!), full **scheduler** (cron/daily/weekly/monthly, `NextRunAt`), **retry/backoff**, **timeout**, agent routing, profiles, runs/sessions (`run.go`, `session.go`, `scheduler.go`, `trigger.go`). Controllers `scan_retry`, `scan_timeout` already exist.
- **The partial-coverage safety invariant is ALREADY enforced.** The ingest path computes `toolName := report.Tool.Name` + `scanID := report.Metadata.ID` and calls `AutoResolveStaleByAssets(tenantID, assetIDs, toolName, scanID, nil)` (`internal/app/ingest/service.go:271`) — auto-resolve is scoped to **(this tool) × (these asset IDs) × (this scan)**. A batch of 500 cannot resolve the other 2500, *and* a Tenable scan cannot resolve nuclei/trivy findings. The requirement reduces to: **the .nessus→CTIS adapter must emit one report per batch carrying `tool.name="tenable"`, a unique per-batch `metadata.id` (scan session), and only that batch's assets.**
- **Nessus XML parser scaffold** (`internal/app/asset/import.go`): parses `NessusClientData_v2 → ReportHost → ReportItem` (already models `pluginName`/`severity`) — but **only creates host assets, discards vulnerabilities**. No findings ingestion from .nessus yet. *Both* Pro and .sc export the same `.nessus` format, so one adapter serves both.
- **Async ingest** (RFC-005): queue + worker, multi-row insert, dedup/correlation, idempotency.
- **Integration model**: `ProviderTenable` enum present, AES-256-GCM encrypted credentials, `Config()`/`Metadata()` JSONB, and the **per-tenant client-resolver pattern** just shipped for Jira (RFC-006 Phase 0) — the exact precedent for a per-tenant Tenable engine resolver.
- **Asset inventory**: `Criticality` + **`LastScannedAt`** (`asset/repository_extension.go`) — the rotation cursor.

**Build gaps:** (1) `.nessus → CTIS findings` adapter; (2) `ScanEngine` connector (Nessus Pro + .sc); (3) coverage rotation scheduler; (4) coverage/license observability + UI.

## 2. Goals / Non-goals

**Goals**
1. OpenCTEM is the durable **system-of-record** for the full estate; the scanner holds at most one batch.
2. **Both engines first-class** behind one `ScanEngine` interface + `LicensePolicy`.
3. **Partial-coverage-safe** ingestion (reuse the already-scoped auto-resolve).
4. **License-aware scheduling**: criticality-weighted, least-recently-scanned rotation that fits the active license; `.sc` cap enforced as a hard constraint.
5. **No data loss**: never free a scanner slot before results are verifiably stored.

**Non-goals**
- Replacing Tenable as the scan engine, or building Qualys/OpenVAS now (the seam should generalise later).
- Real-time scanning — this is scheduled rolling coverage.
- A `.io` rotation mode (its 90-day count makes rotation moot).

## 3. Proposed design

### 3.1 `ScanEngine` abstraction (both engines behind one seam)

```go
type ScanEngine interface {
    Kind() string                                          // "nessus_pro" | "tenable_sc"
    LicensePolicy() LicensePolicy
    Launch(ctx, EngineScanRequest) (EngineRef, error)      // targets (IP/CIDR), policy/template; sc: repository + asset list
    Poll(ctx, EngineRef) (EngineScanStatus, error)         // pending|running|completed|failed + progress
    Export(ctx, EngineRef) (io.ReadCloser, error)          // .nessus stream (both engines)
    Reclaim(ctx, ReclaimRequest) error                     // pro: no-op; sc: remove/age the batch's IPs
    TestConnection(ctx) error
}

type LicensePolicy struct {
    Mode    LicenseMode  // Unlimited | ActiveIPCap
    Cap     int          // active-IP cap (.sc)
    Reclaim ReclaimMode  // None | Remove | Age
}
```

- **Nessus Pro impl** — Nessus REST on the scanner host: `POST /scans` (`settings.text_targets`), `POST /scans/{id}/launch`, `GET /scans/{id}` (status), `POST /scans/{id}/export?format=nessus` → poll export status → download. Auth `X-ApiKeys: accessKey=…; secretKey=…`. `Reclaim` = no-op (optional scan-history cleanup for housekeeping only).
- **Tenable.sc impl** — `/rest` API: `POST /scan` (policy + asset list/target + repository), `POST /scan/{id}/launch`, `GET /scanResult/{id}` (status), download `.nessus`. Auth `x-apikey access/secret`. `Reclaim` = remove the batch's IPs/results from the repository (immediate slot free), with short repository data-expiration as a passive backstop.
- Per-tenant resolution mirrors the Jira client resolver: load the `provider=tenable` integration, read `config.engine` (`nessus_pro`|`tenable_sc`) + `base_url`, decrypt credentials JSON `{access_key, secret_key}`, build the right engine.

### 3.2 Tenable.sc active-IP accounting (how the cap is actually respected)

The `.sc` license counts IPs with vuln data in repositories. To keep ≤ cap while covering the estate, use a **dedicated OpenCTEM rotation repository** and make `Reclaim` an **explicit removal** of the just-ingested batch's IPs:

```
active_ip_set ≈ IPs with live results in the rotation repo
invariant: |active_ip_set| ≤ Cap − safety_margin
per cycle: assert(|active_ip_set| + |batch| ≤ Cap) → Launch → … → ingest ACK → Reclaim(batch) → active_ip_set shrinks
```

Because `.sc` removal frees the count **immediately** (unlike `.io`'s 90-day lag), the steady state is `active ≈ current batch ≤ Cap`. Aging (short data-expiration on the repo) is the belt-and-braces fallback if an explicit removal is missed. The scheduler tracks `active_ip_set` itself rather than trusting instant reclaim, so a slow removal just delays the next launch instead of breaching the cap.

### 3.3 Coverage rotation — extend the existing Scan, don't rebuild

Model a coverage sweep as a **scheduled `Scan`** over the estate asset group with `ScannerName="tenable"`, `TargetsPerJob = license headroom` (e.g. 500), executed against the `ScanEngine` instead of an agent. Add one selection strategy on top of the existing batching:

```
coverage rotation select(next batch, size = TargetsPerJob):
  candidates = assets in scope, not in-flight
  order by (criticality_weight DESC, LastScannedAt ASC NULLS FIRST)
  take first N where Σ(ip_count(asset)) ≤ headroom        // count IPs, not hostnames (CIDR aware)
on run completion (ingest ACK):
  set LastScannedAt = now for batch assets
  (ActiveIPCap engines) Reclaim(batch)                    // gated on ACK
  advance cursor; scheduler computes NextRunAt for the next batch
```

Criticality-weighting means `critical` assets are re-scanned more often than `none`, instead of a flat 6-cycle round-robin. The existing scheduler/retry/timeout/run machinery is reused wholesale; "coverage rotation" is just a batch-selection policy + a reclaim hook.

### 3.4 Findings ingestion (`.nessus → CTIS`) + the safety rule

Extend the existing Nessus parser into a findings adapter: `ReportHost → asset`, `ReportItem → finding` (map Nessus `severity 0–4` / `cvss_base_score` / `cve` / `pluginID` / `plugin_output` / `solution` / `risk_factor` → CTIS finding fields). Emit **one CTIS report per batch** with `tool.name="tenable"` and a unique `metadata.id` (= the scan session id), containing only the batch's assets. Route through async ingest → dedup/correlation/idempotency + the **already-scoped** `AutoResolveStaleByAssets` come for free (§1). This is the single most important correctness property and it is satisfied by construction once the adapter sets tool/scan/asset scope correctly.

### 3.5 Reclaim gated on verified ingest

Freeing a scanner slot (`.sc` removal) happens **only after** the batch is exported, ingested, and ACKed, and the raw `.nessus` is archived. On failure the cycle retries (reuse scan retry/backoff); the scanner keeps the batch; the cursor does not advance.

### 3.6 Observability

- Per-asset **last-scanned age**; estate freshness histogram.
- **Sweep cadence** (time to cover the whole estate) overall and per criticality tier.
- **`.sc` license utilisation** (tracked `active_ip_set` vs `Cap`) so scheduler headroom is visible.
- Metrics via `internal/metrics` (Prometheus) as in RFC-005.

## 3.9 Execution model: runner-mediated (polling) is the default

### Deployment & trust model (the driving requirement)

The expected production topology has the **OpenCTEM runner, Nessus, and Tenable
all in the production zone**, while the **OpenCTEM control plane (api) sits in a
separate zone**. The security requirement is that **the control plane holds as
little authority over Nessus/Tenable as possible** — it must not store scanner
credentials nor open connections into the production zone.

This dictates a **runner-mediated, poll-based** design:

```
   ┌── production zone ───────────────────────┐        ┌── control zone ──────┐
   │  OpenCTEM runner ──► Nessus / Tenable     │        │   OpenCTEM api       │
   │       │  (holds creds locally)            │        │   (no scanner creds, │
   │       └── outbound poll / push ───────────┼───────►│    no inbound access)│
   └───────────────────────────────────────────┘        └──────────────────────┘
        only OUTBOUND connections cross the zone boundary
```

- The **runner** is the *only* component with Nessus/Tenable credentials and the
  *only* one that connects to the appliances — both stay inside the prod zone.
- The runner reaches OpenCTEM **outbound only**: it long-polls for jobs and pushes
  results. The api **never** initiates a connection into the prod zone and never
  needs a network path to Nessus/Tenable.
- Blast radius: compromising the control plane yields **no** scanner credentials
  and **no** prod-network access. This is the whole point.

This reuses OpenCTEM's existing **platform-agent machinery** (bootstrap-token
register → lease → `POST /platform/poll` long-poll → job `ack`/`progress`/`result`,
CTIS push via `PushCTIS`), so it is not new transport — just a new `tenable`
capability on the runner.

### The two modes

A Tenable integration declares `config.execution_mode`:

- **`agent` (runner-mediated, polling) — DEFAULT / recommended.** The runner in the
  prod zone runs the scan against the local appliance and pushes CTIS back. The api
  holds no creds and never reaches the appliance. This satisfies the trust model
  above and is the path we build first.
- **`direct` — optional, only when the operator accepts api↔Tenable.** The api
  calls Tenable REST itself. Appropriate only for Tenable **cloud** or a
  deliberately-allowed reachable `.sc` where the operator accepts the control plane
  holding creds. Not for the segmented prod-zone case.

Everything *above* the execution boundary is identical in both modes: the coverage
scheduler (§3.3), license accounting (§3.2), the `.nessus → CTIS` parser (§3.4), the
ingest pipeline + batch-scoped auto-resolve (§1), mapping, and tenant isolation.
Only *where the Tenable REST calls happen* differs.

### Layered design (so the two modes share, not duplicate)

```
   Coverage scheduler (Phase 3)               ── mode-agnostic
        │ runner.Run(session, batch)
        ▼
   ScanEngineRunner  (strategy)
   ├─ DirectRunner (api)   → in-process TenableClient → .nessus → ingest inline
   └─ AgentRunner  (api)   → dispatch agent job ──► agent runs TenableClient ──► PushCTIS
        ▲                                                    │
        └──────────── shared building blocks ───────────────┘
   L1 TenableClient   : Launch/Poll/Export/Reclaim (Nessus Pro + .sc REST)
   L2 .nessus parser  : ReportItem → ctis.Finding  (the existing converter)
```

- **L1 `TenableClient`** and **L2 parser** are the *same code* in both modes — they
  just execute in a different process. They take an **injectable HTTP client** so
  the api supplies its SSRF-safe `pkg/httpsec` client and the agent supplies its
  own. No Tenable logic is written twice.
- **`ScanEngineRunner`** is the only mode-specific layer:
  - `DirectRunner` (api): per-tenant resolver builds a `TenableClient`
    (mirrors the Jira client resolver — `ListByProvider(tenantID, ProviderTenable)`,
    decrypt creds), runs L1→L2, ingests with the coverage `session_id`.
  - `AgentRunner` (api): creates a scan job/command for an agent advertising the
    `tenable` capability, carrying `{engine, base_url, targets, session_id,
    credential_ref}`. The agent runs L1→L2 and `PushCTIS` back to the api ingest
    endpoint, stamping `metadata.id = session_id` so the scheduler correlates the
    result to the batch.

### Code ownership (respects the RFC-002 api↔sdk-go decoupling)

| Component | Home | Used by |
|-----------|------|---------|
| L2 `.nessus → CTIS` parser | promote to the shared **`ctis` module** (zero-dep) | api (direct) + sdk-go/agent (agent) — one copy |
| L1 `TenableClient` (REST, stdlib + ctis types, injectable HTTP) | a small shared package both can import | api (direct) + sdk-go `pkg/scanners/tenable` wrapper (agent) |
| `DirectRunner`, per-tenant resolver | api `internal/infra/scanner/tenable` | api only |
| `AgentRunner` (job dispatch) | api (scan orchestration) | api only |
| `tenable` executor/tool | agent `vulnscan` executor | agent only |

The api stays decoupled from the *whole* sdk-go: it imports only the shared parser
(`ctis`) and the small Tenable client package — not `sdk-go`. The agent imports the
same two via its existing `sdk-go` dependency. The today's api-internal converter
(`internal/infra/scanner/nessus`) is migrated into the shared parser as the first
step so there is never a second copy.

### Credential locality (a security win for `agent` mode)

- **`direct`**: creds live encrypted in the integration; the api decrypts per
  request (AES-256-GCM), exactly like Jira.
- **`agent`**: prefer **agent-local credentials** — the on-prem agent is configured
  with access to its local Tenable; the api job says only "scan these targets for
  session X" and the api **never holds the on-prem Tenable creds**. (Fallback: the
  api may pass a credential reference over the authenticated agent channel, but
  agent-local is the recommended posture for segmented networks.)

### Tenant isolation in both modes

- `direct`: per-tenant resolver — `ListByProvider(tenantID, ProviderTenable)` is
  `WHERE tenant_id=$1` → a tenant only ever uses its own Tenable creds.
- `agent`: the job is created for a tenant and routed only to an agent authorised
  for that tenant; agent-pushed CTIS derives tenant from the **authenticated
  agent**, never from the `.nessus` file (same guarantee as all agent ingest).

### Result correlation & reclaim (runner-mediated)

The coverage `session_id` is the join key. The api dispatches a job carrying it;
the runner stamps it into the pushed report so the scheduler correlates the result
to the batch. Because **only the runner can reach the appliance**, the runner owns
the `.sc` reclaim (remove the batch's IPs) and performs it after the api ACKs the
push, then reports reclaim completion via the job `result`. The api's `active_ip_set`
accounting is authoritative for *dispatch* (it won't release the next batch until
the runner confirms the prior batch's reclaim), while the runner is authoritative
for the *appliance*. Auto-resolve is gated on ingest ACK as everywhere else.

`direct` mode (optional) ingests inline and reclaims from the api.

### Runner job lifecycle (reuses platform-agent transport)

```
api: scheduler picks batch B for session S  ──► enqueue tenable job {engine, targets:B, session:S}
runner: POST /platform/poll (long-poll, outbound) ──► claims job
runner: TenableClient.Launch(B) → poll local appliance → Export(.nessus) → parse → PushCTIS(session=S)
runner: POST /jobs/{id}/progress … then result; on api ingest-ACK → reclaim B locally → result=done
api: scheduler marks B scanned (LastScannedAt), frees active_ip_set, advances cursor
```

No new transport — the `tenable` capability rides the existing register/lease/poll/
ack/result machinery.

### Does the agent / sdk-go need work?

- **Runner-mediated mode (the default for the segmented prod-zone topology): YES** —
  this is the primary path. sdk-go gets the shared `TenableClient` + parser, and the
  agent gets a `tenable` tool in its `vulnscan` executor. The api gets only the
  `AgentRunner` (job dispatch) — **no Tenable client and no scanner creds in the api**.
- **`direct` mode (optional):** api-side only; agent/sdk-go need nothing.
- **Today (Phase 1, shipped):** the manual `POST /assets/import/nessus-findings`
  upload already covers a prod-zone appliance via an external cron — a working
  stopgap until the runner `tenable` tool ships.

## 4. Roadmap (both engines)

1. **Phase 1 — Findings ingestion + safety (lowest risk, highest de-risk).** `.nessus → CTIS findings` adapter; emit per-batch report with `tool=tenable` + session `scanID` + batch assets; confirm batch-scoped auto-resolve end-to-end with **manual `.nessus` files from both Pro and .sc** (both export the same format). No connector needed yet — validates the invariant and the parser for both engines at once.
2. **Phase 2 — `TenableClient` + execution modes (§3.9), runner-mediated first.** Sequenced so the (default) runner mode lands first and `direct` reuses the same core:
   - **2a — Shared core:** migrate the `.nessus → CTIS` parser into the shared `ctis` module; build `TenableClient` (Nessus Pro + `.sc` REST, injectable HTTP client) + `LicensePolicy`; `TestConnection`. (Lives where sdk-go/agent can import it.)
   - **2b — `agent` (runner-mediated) mode — PRIMARY:** agent `tenable` tool in the `vulnscan` executor reusing the shared client/parser, **agent-local credentials**, capability advertising; api `AgentRunner` dispatches the job (session_id) over the existing poll/lease machinery + tenant-scoped routing. **The api holds no Tenable creds.**
   - **2c — `direct` mode — OPTIONAL:** `DirectRunner` + per-tenant resolver (`ListByProvider(tenantID, ProviderTenable)`, decrypt creds — mirrors Jira Phase 0) for tenants who accept api↔Tenable (cloud / reachable `.sc`).
3. **Phase 3 — Coverage scheduler.** Coverage-rotation selection (criticality + staleness, CIDR-aware IP counting), `TargetsPerJob` batching, `.sc` cap enforcement via tracked `active_ip_set`, Reclaim gated on ingest ACK, `LastScannedAt` advance, retry/timeout reuse.
4. **Phase 4 — Observability + UI.** Coverage freshness, `.sc` license utilisation, sweep cadence; Discovery → "Scan Coverage" page + Tenable integration config UI under settings/integrations (security category).
5. **Phase 5 (optional) — Generalise the seam** for a third scanner (Qualys/OpenVAS) and a Nessus-Agents commercial option.

## 5. Alternatives considered

- **Nessus Pro only, ignore the cap** — valid for breadth (Pro is unlimited), but the customer explicitly needs `.sc` too (managed scanners reach segmented networks, compliance/dashboards). Support both.
- **Tenable Nessus Agents** — licensed by agent count; for 3000 internal hosts often cheaper and removes network-scan license pressure. Worth a commercial evaluation; orthogonal to this design (agents still feed `.nessus`/`.sc`).
- **Hard delete-and-recreate to dodge a cap** — the original idea. On `.sc` this is exactly `Reclaim: Remove` done safely (gated on ingest, repo-scoped). On `.io` it doesn't reclaim in time and risks licensing terms — excluded.
- **External cron script orchestrates, OpenCTEM only ingests** — fine for the Phase 1 pilot (manual `.nessus` import), but leaves coverage/scheduling invisible; move orchestration into OpenCTEM (Phases 2–3).
- **Build parallel coverage tables/scheduler** — rejected; the existing `Scan` (TargetsPerJob, scheduler, retry, runs) already models batched scheduled scanning. Extend it.

## 6. Open questions

- Nessus Pro standalone vs scanners *managed by* `.sc` — talk to Nessus REST directly, drive everything via `.sc`, or both per integration? (`config.engine` already allows per-integration choice.)
- Exact `.sc` removal endpoint for immediate IP reclaim vs relying on repository aging — confirm during Phase 2 spike.
- Severity: trust Nessus severity, CVSS base, or platform re-scoring (RFC-004 EPSS/KEV)? Likely keep raw + re-score downstream.
- Dead/unreachable hosts: does "scanned but host down" advance `LastScannedAt`? (Proposal: track a separate `last_attempted_at` vs `last_assessed_at` so coverage metrics aren't inflated by unreachable hosts.)
- Batch vs scan duration: a 500-IP authenticated scan can take hours — what sweep SLA per criticality tier?
- Least-privilege API key scopes per engine (scan + export; `.sc`: asset/repository manage for reclaim) — document required permissions.
- `agent`-mode credentials: agent-local (recommended, api never holds on-prem creds) vs api-passed credential reference over the agent channel — confirm the agent's local config story and whether any tenants need api-managed creds.
- Shared `TenableClient` home: a standalone small package vs living beside the parser in the `ctis` module — must stay importable by both api and sdk-go without re-coupling api to the whole `sdk-go` (RFC-002).
- `agent`-mode reclaim/long-poll: the agent must keep the `.sc` cap respected during a multi-hour scan it owns; does the scheduler's `active_ip_set` accounting move to the agent for agent-mode, or stay api-side with the agent reporting progress?

## 7. Risks

- **Partial-coverage mis-resolve** — the central invariant; already enforced by the scoped `AutoResolveStaleByAssets` (§1, §3.4). Phase 1 must prove it with a 2-batch test.
- **Premature reclaim / data loss** — mitigated by gating reclaim on verified ingest (§3.5).
- **`.sc` cap breach from reclaim lag** — mitigated by scheduler-tracked `active_ip_set` + safety margin (§3.2), not by assuming instant removal.
- **Licensing/TOS** — only `.sc` repo-scoped removal/aging is endorsed; no churn-to-dodge on asset-counted products.
- **Detection latency** — an asset is re-scanned each sweep; criticality-weighting bounds it for what matters, and the freshness dashboard makes it visible.
- **Tool coexistence** — Tenable findings must not resolve agent-scanner (nuclei/trivy) findings; guaranteed by `toolName` scoping in auto-resolve (§1).
