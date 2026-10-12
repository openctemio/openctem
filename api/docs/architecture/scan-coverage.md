# License-Aware Scan Coverage (Tenable Nessus Pro + Tenable.sc)

> **Status**: `.nessus` uploads go through the shared ctis importer
> (`POST /findings/import`, [finding-import.md](finding-import.md)). The live connector and the coverage scheduler are **paused** (owner
> decision D-14): sensor v0.8.0 removed the Tenable runner, so new Tenable
> integrations are refused, the scheduler is not registered and the web hides
> Connect/Edit/Coverage, all behind one switch
> (`integration.TenableConnectorEnabled`, web `TENABLE_CONNECTOR_ENABLED`).
> Rebuild: RFC-047 (two-way Tenable.sc connector in the sensor). Design in
> [RFC-007](../rfcs/RFC-007-license-aware-scan-coverage.md). Complements
> [Scan Orchestration](scan-orchestration.md) (sensor-run scanners); this doc
> covers **external** Tenable engines.

> **Superseded design (2026-10-04).** Coverage now runs on the Tenable.sc
> sensor connector ([RFC-047](../rfcs/RFC-047-tenable-sc-sensor-connector.md)
> §9, [tenable-sc-connector.md](tenable-sc-connector.md#rolling-coverage-p2)):
> each batch is a `connector_scan`, sized against Tenable.sc's own licensed and
> active IPs. The runner and direct modes described below are gone; the
> planner, cursor and batch-scoped auto-resolve invariant are kept.

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
   ctis importer (.nessus)  ──►  *ctis.Report   (github.com/openctemio/ctis/importer)
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
- a Tenable scan cannot resolve sensor-scanner (nuclei/trivy) findings.

The requirement on the converter is therefore narrow: emit **one report per
batch** with `tool.name="tenable"`, a unique `metadata.id` (the scan session),
`coverage_type="full"`, and only that batch's hosts.

> **Not working today (verified 2026-10):** ingest's auto-resolve requires a
> default branch, built for CI/SAST scans. The converter emits a **synthetic**
> `Branch{IsDefaultBranch:true}` to pass the report-level gate, but branches are
> only tracked for repository assets and the auto-resolve query joins findings
> to the repository's default branch, so host findings (`branch_id` NULL) are
> never matched. Uploading a batch that no longer contains a finding leaves it
> open. Non-repository findings do not auto-resolve by design (see
> `shift-left-ci-scanning.md`, "Which findings auto-resolve"); making this one
> server-side, batch-scoped path an exception is an open product decision.

## `.nessus → CTIS` conversion

One parser: the ctis importer (`importer.FormatNessus`), shared by every
upload path. Nessus Pro and Tenable.sc write the same `NessusClientData_v2`
format. The mapping, field by field, is the importer's spec
(`docs/importers/nessus.md` in the ctis repository): one asset per host with
its identity hints, one finding per plugin result or compliance check, every
CVSS version, VPR and EPSS, typed vulnerability ids, advisories, KEV and
exploit flags. The scan policy (credentials) is never read; plugin output and
compliance values are redacted of accounts, passwords, tokens and community
strings. Every finding carries a network location (port 0 = host level), so
the receiver keys it on the network identity (host, CVE or plugin,
port/protocol).

## Upload endpoint

Until the live Tenable connector lands, results enter OpenCTEM by uploading a
`.nessus` export (or a ZIP of them) to `POST /api/v1/findings/import`
([finding-import.md](finding-import.md)). Settings → Vulnerability scanners
sends `?min_severity=low` to skip informational results. The upload runs with
the uploader's rights and is always partial coverage: it never auto-resolves.
The earlier `POST /assets/import/nessus` (hosts only) and
`POST /assets/import/nessus-findings`, with their own parser, are removed.

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

## Two execution modes (both first-class)

A Tenable integration runs in one of two selectable modes (`config.execution_mode`),
sharing everything above the execution boundary — scheduler, parser, ingest,
mappings, isolation. Only *where the Tenable REST calls run* differs:

- **`direct`** — the backend calls Tenable REST itself (cloud, or reachable `.sc`).
  api-side `DirectRunner` + per-tenant resolver. **No sensor/sdk-go work.**
- **`sensor`** — a purpose-built sensor on the customer network calls the local
  appliance and pushes CTIS back (on-prem `.sc` the api can't reach). Adds a sensor
  `tenable` tool + a shared `TenableClient`/parser; api-side `AgentRunner` dispatches
  the job carrying the coverage `session_id`. Credentials can stay **sensor-local**
  (api never holds on-prem creds).

The two modes share the L1 `TenableClient` (REST, injectable HTTP) and the L2
`.nessus → CTIS` parser; only the thin `ScanEngineRunner` strategy differs. The
parser is promoted to the shared `ctis` module so api and sensor use one copy.
Full design + code-ownership + tenant-isolation in
[RFC-007 §3.9](../rfcs/RFC-007-license-aware-scan-coverage.md).

Today (Phase 1): on-prem unreachable from the api is already covered by an external
cron pushing `.nessus` to `POST /findings/import` — no sensor needed yet.

### Configuring a Tenable integration (shipped)

A `provider=tenable` integration carries `config.execution_mode` (`sensor` default |
`direct`) and `config.engine` (`nessus_pro` default | `tenable_sc`). Creation is
validated server-side (`internal/app/scancoverage/tenable_config.go`):

- **sensor mode MUST NOT store credentials in the control plane** (RFC-007 §8 R3/R4)
  — they belong on the runner; supplying credentials is rejected.
- **direct mode requires credentials + base_url** (the api calls Tenable).
- unknown `execution_mode`/`engine` values are rejected; config is normalized so the
  stored record always carries explicit values.

The create-integration endpoint now accepts a `config` object to set these.

### Automatic rolling coverage (Phase 3, shipped — unlimited engine)

Set these extra `config` keys on a `provider=tenable` integration to opt it into
automatic, license-aware rolling coverage:

| Key | Meaning | Default |
|-----|---------|---------|
| `coverage_enabled` | Opt into auto-rotation (off → integration is just a connection) | `false` |
| `batch_size` | Per-cycle batch (perf/time window) | `256` |
| `agent_id` | Pin a specific runner (C3); omit → capability routing | — |
| `template_uuid` | Override the runner's Nessus template | — |
| `license_cap` / `safety_margin` | Active-IP cap for `tenable_sc` | — |

The **coverage scheduler** (`internal/infra/controller/coverage_scheduler.go`) runs
every 5 minutes: it lists coverage-enabled Tenable integrations cross-tenant, sizes a
batch against the engine's license headroom (`internal/app/scancoverage/scheduler.go`
→ `planner.go`), dispatches it to a runner
(`internal/app/scancoverage/dispatcher.go` → a `scan` command with `scanner=tenable`),
and advances the rotation cursor (`scan_coverage_state`, migration 000176) so the same
assets sort last next cycle. The runner scans its local appliance and pushes CTIS back;
ingest auto-resolve is scoped to the batch's `session_id` + assets.

Every batch passes the checks of a scan trigger before it is claimed
(`scan.Service.ResolveDispatchTargets`, RFC-042 F16): scan create's target
validator (a private address only inside a scan zone; loopback, link-local and
metadata never), approved scope exclusions, the attribution of the candidate
asset (an asset whose ownership is not confirmed is skipped, RFC-036 O4), and
zone routing ([active-probe-gate.md](active-probe-gate.md)). A skipped asset
is claimed without a dispatch, so it rotates to the back and is checked again
on its next turn. A batch stays in the zone of its top candidate, the command
is stamped with that zone, and a pinned sensor must be in it. No gate, or a
failed exclusion or attribution lookup, dispatches nothing. Internal networks therefore need
a scan zone covering them, as for any other scan.

> **Scope:** today the scheduler drives only **unlimited engines (Nessus Pro)** —
> exactly the 3000-IP-on-Nessus-Pro use case. **Capped engines (Tenable.sc) are
> skipped** (logged) until active-IP accounting + reclaim-ACK ship (Phase 3.5):
> dispatching them without that accounting could exceed the license, which the
> scheduler refuses to risk.

## Roadmap (RFC-007)

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `.nessus → CTIS` findings adapter + batch-scoped safety + manual ingest endpoint | **Done** — now the ctis importer + `POST /findings/import` |
| 2 | `ScanEngine` connector (Nessus Pro + Tenable.sc) + runner executor | **Done (mock-first)** — sdk-go tenable client/parser, sensor `TenableExecutor`; live-appliance REST verification pending |
| 3 | Coverage scheduler (rotation cursor, dispatch, license headroom) | **Done (unlimited engine)** — planner + dispatcher + scheduler + live controller + `scan_coverage_state` |
| 3.5 | `.sc` active-IP accounting + reclaim gated on ingest ACK | Planned |
| 4 | Observability (freshness, coverage %) | **Done (API)** — `GET /api/v1/scans/coverage`; UI pending |

### Coverage observability (Phase 4, shipped — API)

`GET /api/v1/scans/coverage?window_days=30` (JWT; `scans:read`) returns a
tenant-scoped coverage summary so rolling scans become *verifiable*:

```json
{
  "window_days": 30, "total_scannable": 3000, "never_scanned": 500,
  "covered_in_window": 2400, "stale": 100,
  "critical_never_scanned": 3, "critical_uncovered": 5,
  "oldest_dispatched_at": "2026-05-02T...", "coverage_percent": 80.0
}
```

Computed by `ScanCoverageRepository.CoverageStats` (one conditional-aggregation
query over the scannable estate LEFT JOIN `scan_coverage_state`). `coverage_percent`
= covered-in-window / total. The headline risk metric is `critical_never_scanned`.

## Key files

```
internal/app/findingimport/                    .nessus (and other exports) → ctis importer → ingest
internal/app/scancoverage/planner.go           LicensePolicy + batch selection (pure core, shipped)
internal/app/scancoverage/dispatcher.go         build scan command routed to a tenable runner (shipped)
internal/app/scancoverage/scheduler.go          rotation pass: headroom -> select -> dispatch -> cursor (shipped)
internal/app/scancoverage/tenable_config.go     parse config (engine/mode/coverage_enabled/batch/cap) (shipped)
internal/infra/controller/coverage_scheduler.go live controller binding the scheduler to repos (shipped)
internal/infra/postgres/scan_coverage_repository.go  candidates + rotation cursor (shipped)
migrations/000176_scan_coverage_state.up.sql    per-asset rotation cursor table (shipped)
internal/app/ingest/service.go                 scoped auto-resolve (safety invariant)
pkg/domain/scan/entity.go                       Scan.TargetsPerJob, scheduler
```
