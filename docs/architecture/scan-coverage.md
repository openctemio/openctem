# License-Aware Scan Coverage (Tenable Nessus Pro + Tenable.sc)

> **Status**: Converter shipped (#139). Connector + scheduler designed in
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

## Roadmap (RFC-007)

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `.nessus → CTIS` findings adapter + batch-scoped safety | **Converter done** (#139); upload/ingest wiring with connector |
| 2 | `ScanEngine` connector (Nessus Pro + Tenable.sc) + per-tenant resolver | Planned |
| 3 | Coverage scheduler (rotation, `.sc` cap, reclaim gated on ACK) | Planned |
| 4 | Observability (freshness, license utilisation, sweep cadence) + UI | Planned |

## Key files

```
internal/infra/scanner/nessus/converter.go    .nessus → *ctis.Report (shipped)
internal/app/asset/import.go                   ImportNessus (asset-only legacy path)
internal/app/ingest/service.go                 scoped auto-resolve (safety invariant)
pkg/domain/scan/entity.go                       Scan.TargetsPerJob, scheduler
pkg/domain/asset/repository_extension.go        LastScannedAt (rotation cursor)
```
