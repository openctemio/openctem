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

## 4. Roadmap (both engines)

1. **Phase 1 — Findings ingestion + safety (lowest risk, highest de-risk).** `.nessus → CTIS findings` adapter; emit per-batch report with `tool=tenable` + session `scanID` + batch assets; confirm batch-scoped auto-resolve end-to-end with **manual `.nessus` files from both Pro and .sc** (both export the same format). No connector needed yet — validates the invariant and the parser for both engines at once.
2. **Phase 2 — `ScanEngine` connector.** Interface + `LicensePolicy`; **Nessus Pro** impl (unlimited, simplest) and **Tenable.sc** impl (cap + repository/asset-list + Reclaim removal); per-tenant resolver (mirror Jira RFC-006 Phase 0); `TestConnection`; a manual "scan this target list now → ingest" trigger.
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

## 7. Risks

- **Partial-coverage mis-resolve** — the central invariant; already enforced by the scoped `AutoResolveStaleByAssets` (§1, §3.4). Phase 1 must prove it with a 2-batch test.
- **Premature reclaim / data loss** — mitigated by gating reclaim on verified ingest (§3.5).
- **`.sc` cap breach from reclaim lag** — mitigated by scheduler-tracked `active_ip_set` + safety margin (§3.2), not by assuming instant removal.
- **Licensing/TOS** — only `.sc` repo-scoped removal/aging is endorsed; no churn-to-dodge on asset-counted products.
- **Detection latency** — an asset is re-scanned each sweep; criticality-weighting bounds it for what matters, and the freshness dashboard makes it visible.
- **Tool coexistence** — Tenable findings must not resolve agent-scanner (nuclei/trivy) findings; guaranteed by `toolName` scoping in auto-resolve (§1).
