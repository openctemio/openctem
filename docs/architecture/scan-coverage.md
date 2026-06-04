# License-Aware Scan Coverage (Tenable Nessus Pro + Tenable.sc)

> **Status**: Converter (#139) + manual `.nessus` ingest endpoint shipped.
> Live connector + scheduler designed in
> [RFC-007](../rfcs/RFC-007-license-aware-scan-coverage.md). Complements
> [Scan Orchestration](scan-orchestration.md) (agent-run scanners); this doc
> covers **external** Tenable engines.

## Problem

Cover a large estate (e.g. 3000 IPs) with a scanner licensed for fewer active
IPs (e.g. 500), by scanning in rolling, license-sized batches and storing every
result durably in OpenCTEM — **without** wrongly resolving findings for assets
that were not in the current batch.

OpenCTEM is the **system of record** for the full estate; the scanner holds at
most one batch at a time.

## Engines (both first-class)

| Engine | License unit | Reclaim | Rotation |
|--------|--------------|---------|----------|
| **Nessus Professional** | per scanner, **unlimited IPs** | n/a | not needed — batch = perf/time only |
| **Tenable.sc** | **active IPs** (cap) | explicit removal (immediate) + repo aging | first-class — scheduler enforces the cap |
| *(Tenable.io, ref)* | assets, 90-day count | deletion lag ~90d | excluded — can't reclaim in time |

A single `ScanEngine` interface with a per-engine `LicensePolicy`
(`Unlimited` vs `ActiveIPCap` + `Reclaim`) lets the scheduler treat both
identically: it reads the policy to size batches and decide whether a reclaim
step runs.

## End-to-end flow

```
   estate (all assets, Criticality + LastScannedAt)
            │  coverage rotation: order by (criticality DESC, LastScannedAt ASC)
            ▼
   select next batch (size = license headroom, e.g. 500)
            │
            ▼
   ScanEngine.Launch(targets) ─poll─► Export(.nessus)
            │
            ▼
   nessus.Convert(.nessus)  ──►  *ctis.Report   (internal/infra/scanner/nessus)
            │   tool=tenable · metadata.id=session · coverage=full · synthetic default branch
            ▼
   ingest pipeline (RFC-005 async)
            │   AutoResolveStaleByAssets(tenant, assetIDs=BATCH, tool, scanID)
            ▼
   findings stored + stale-resolved ONLY within the batch
            │
            ▼
   set LastScannedAt(batch); (.sc) Reclaim(batch) gated on ingest ACK; advance cursor
```

## The safety invariant (most important property)

Each batch covers only N of the estate. Auto-resolve **must** touch only the
batch's assets. This is **already enforced** by the ingest pipeline: it calls
`AutoResolveStaleByAssets(tenantID, assetIDs, toolName, scanID, branchID)`
scoped to **(this tool) × (these asset IDs) × (this scan)**
(`internal/app/ingest/service.go`). So:

- a 500-IP batch cannot resolve the other 2500 assets' findings;
- a Tenable scan cannot resolve agent-scanner (nuclei/trivy) findings.

The requirement on the converter is therefore narrow: emit **one report per
batch** with `tool.name="tenable"`, a unique `metadata.id` (the scan session),
`coverage_type="full"`, and only that batch's hosts.

> **Note (git-centric gate):** ingest's auto-resolve also requires a default
> branch (`IsDefaultBranchScan()`), built for CI/SAST scans. Network scans have
> no branch, so the converter emits a **synthetic** `Branch{IsDefaultBranch:true}`.
> A cleaner long-term fix is to make the gate treat non-git source types as
> eligible without a synthetic branch.

## `.nessus → CTIS` converter (shipped, #139)

`internal/infra/scanner/nessus/converter.go` — `Convert(io.Reader, ConvertOptions) (*ctis.Report, error)`.
Both Nessus Pro and Tenable.sc emit the same `NessusClientData_v2` format, so one
converter serves both.

- `ReportHost` → CTIS asset (host/ip_address; FQDN preferred value; ip/os/mac/fqdn in properties).
- `ReportItem` → CTIS vulnerability finding:
  - severity 0–4 → info/low/medium/high/critical;
  - CVE + CVSS (v3 preferred over v2), remediation from `solution`, `see_also` → references;
  - port/protocol/service + extra CVEs + plugin output in finding properties;
  - stable fingerprint `nessus:<host>:<plugin>:<port>/<proto>` for cross-cycle dedup.
- `ConvertOptions`: `ScanSessionID` (→ metadata.id, unique per batch), `ToolName`
  (default `tenable`), `MinSeverity` (drop info noise), `Now` (deterministic tests),
  `DefaultCriticality`.

## Manual / cron ingest endpoint (shipped)

Until the live Tenable connector lands, results enter OpenCTEM by uploading a
`.nessus` export. This is the RFC's Phase 1 pilot path (an external script or
operator pushes each batch's file):

```
POST /api/v1/assets/import/nessus-findings        (JWT; AssetsWrite + FindingsWrite)
  ?session_id=<batch id>   optional — unique per batch (default: generated)
  ?tool=tenable            optional — auto-resolve scope (default: tenable)
  ?min_severity=1          optional — 0..4, drop info noise (default: 1)
  body: the .nessus XML
  → { "scan_session_id": "...", "result": { assets_*, findings_*, findings_auto_resolved, ... } }
```

Each upload is one batch: the handler builds a synthetic agent for the tenant
(mirroring the ingest job processor), runs `nessus.Convert`, and ingests through
the standard pipeline. Stale Tenable findings on the uploaded hosts are
auto-resolved **scoped to that batch only**. Contrast with
`POST /api/v1/assets/import/nessus`, which imports host assets only (no findings).
Handler: `internal/infra/http/handler/asset_import_handler.go` `IngestNessusFindings`.

## Reused infrastructure (do not rebuild)

| Need | Existing primitive |
|------|--------------------|
| Batch size, scheduling, retry, timeout | `pkg/domain/scan` — `Scan.TargetsPerJob`, scheduler, retry/backoff |
| Durable findings + dedup/correlation/idempotency | `internal/app/ingest` (RFC-005 async) |
| Batch-scoped stale resolution | `FindingRepository.AutoResolveStaleByAssets` |
| Rotation cursor | `asset` `Criticality` + `LastScannedAt` |
| Per-tenant credentials | `integration` `ProviderTenable` + AES-256-GCM creds (mirror Jira resolver) |

## Tenable.sc active-IP accounting

Use a dedicated rotation repository; `Reclaim` = **explicit removal** of the
just-ingested batch's IPs (frees the count immediately on `.sc`, unlike `.io`),
with short repo data-expiration as a passive backstop. The scheduler tracks the
`active_ip_set` itself (doesn't trust instant reclaim), so a slow removal delays
the next launch instead of breaching the cap.

## Execution model — runner-mediated (polling) by default

**Trust model (the driving requirement):** the OpenCTEM runner, Nessus, and Tenable
all live in the **production zone**; the OpenCTEM control plane (api) lives in a
**separate zone**. The control plane must hold **minimal authority** over the
scanners — no scanner credentials, no inbound path into prod. So:

- the **runner** is the only component with Nessus/Tenable creds and the only one
  that connects to the appliances (all inside prod);
- the runner talks to OpenCTEM **outbound only** — long-polls for jobs, pushes CTIS
  results — reusing the existing platform-agent transport (register/lease/poll/
  ack/result + `PushCTIS`);
- compromising the control plane yields no scanner creds and no prod access.

A Tenable integration declares `config.execution_mode`:

- **`agent` (runner-mediated, polling) — DEFAULT.** Runner scans the local appliance
  and pushes CTIS back; api holds no creds, never reaches the appliance. Built first.
- **`direct` — OPTIONAL.** api calls Tenable REST itself — only for Tenable cloud /
  a deliberately reachable `.sc` where the operator accepts api↔Tenable.

Both modes share the L1 `TenableClient` (REST, injectable HTTP) + L2 `.nessus → CTIS`
parser; only the thin `ScanEngineRunner` strategy differs. The parser moves to the
shared `ctis` module so api and agent use one copy. The runner owns `.sc` reclaim
(only it can reach the appliance) and reports completion via the job result; the api
scheduler stays authoritative for dispatch/cap accounting. Full design, code
ownership, credential locality, and tenant isolation in
[RFC-007 §3.9](../rfcs/RFC-007-license-aware-scan-coverage.md).

**Security verdict:** this model is secure enough for the segmented topology
*provided* the mandatory controls R1–R4 ship with Phase 2 — runner-side target
validation (don't trust the control plane; reuse `pkg/httpsec` allow-private mode),
rotatable/scoped runner keys + audited pushes, least-privilege Tenable token + no
plaintext creds, and single-tenant runners. See
[RFC-007 §8](../rfcs/RFC-007-license-aware-scan-coverage.md).

Today (Phase 1): a prod-zone appliance is already covered by an external cron pushing
`.nessus` to `POST /assets/import/nessus-findings` — a stopgap until the runner
`tenable` tool ships.

## Roadmap (RFC-007)

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `.nessus → CTIS` findings adapter + batch-scoped safety + manual ingest endpoint | **Done** — converter (#139) + `POST /assets/import/nessus-findings` |
| 2 | `ScanEngine` connector (Nessus Pro + Tenable.sc) + per-tenant resolver | Planned |
| 3 | Coverage scheduler (rotation, `.sc` cap, reclaim gated on ACK) | Planned |
| 4 | Observability (freshness, license utilisation, sweep cadence) + UI | Planned |

## Key files

```
internal/infra/scanner/nessus/converter.go    .nessus → *ctis.Report (shipped)
internal/infra/http/handler/asset_import_handler.go   IngestNessusFindings endpoint (shipped)
internal/app/asset/import.go                   ImportNessus (asset-only legacy path)
internal/app/ingest/service.go                 scoped auto-resolve (safety invariant)
pkg/domain/scan/entity.go                       Scan.TargetsPerJob, scheduler
pkg/domain/asset/repository_extension.go        LastScannedAt (rotation cursor)
```
