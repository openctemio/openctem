# CTEM program metrics

**Status: SHIPPED.** Endpoint: `GET /api/v1/dashboard/program-metrics?days=N`
(`dashboard:read`; `days` 1–365, default 90). Shown on
**Insights → Program Health** in the UI.

These are the program KPIs ctem.org asks a CTEM program to report, restricted to
the ones the platform can compute honestly from data it already stores. The
code that defines them is the source of truth:

| Where | What |
|---|---|
| `internal/app/module/dashboard.go` | `ProgramMetrics`, `DurationMetric`, `OwnerAcceptanceMetric`: the written definitions |
| `internal/infra/postgres/dashboard_program_metrics.go` | The SQL |
| `internal/infra/postgres/dashboard_program_metrics_db_test.go` | Fixtures with known answers, tenant-leak checks, and the empty-tenant case |

## Rules every metric follows

- **Tenant-scoped on every table it reads**, not only the driving one. Each DB
  test seeds a second tenant whose data would change the answer if it leaked.
- **`null` means "not measurable"**: there was no qualifying sample in the
  window. Clients render it as "—". An empty sample is never reported as 0 or
  100%. (The earlier fake ~100% SLA figure, api#444, came from exactly that
  kind of default.)
- Each figure comes with its sample size, so a mean over 2 items is not
  mistaken for a trend.

## The metrics

### 1. MTTD: new internet-facing assets (`mttd_internet_facing`)

- **Population:** non-archived assets first seen in the window that are
  internet-facing now (`exposure = 'public'` or `is_internet_accessible`).
- **Start:** `assets.first_seen`.
- **Stop:** the earliest signal that the asset was known to be internet-facing
  or exposed:
  - `assets.exposure_changed_at`, when the exposure is `public`;
  - `asset_state_history` rows of type `exposure_changed` or
    `internet_exposure_changed` whose new value is `public` or `true`;
  - the asset's first `exposure_events.first_seen_at`;
  - the asset's first `findings.first_detected_at`.
- A stop that falls before `first_seen` counts as 0 h (the asset was known to be
  internet-facing when it was discovered).
- An asset with no stop signal is **not** averaged. It is counted in
  `unmeasured`.
- **Caveat:** `exposure_changed_at` holds only the latest change. An asset that
  went public, then private, then public again is timed to the later change,
  unless an earlier history row, exposure event or finding exists.
- Before this shipped, `Asset.UpdateExposure` (the create, update and import
  path) never stamped `exposure_changed_at`. It stamps it now whenever the level
  changes, so operator classifications carry a timestamp.

### 2. MTTR: validated exposures only (`mttr_validated`)

- **Population:** findings with at least one `validation_evidence` row where
  `outcome = 'detected'`. That outcome means the validation re-check reproduced
  the exposure (RFC-011.2 `VerdictReproducible`, "still exploitable"). The
  finding must now be `resolved` or `verified`, with `resolved_at` in the
  window.
- **Start:** the first `detected` evidence `created_at`.
- **Stop:** `findings.resolved_at`.
- Excluded:
  - findings resolved before they were validated;
  - `false_positive`, `accepted` and `validated_fixed`, because none of them is
    a remediation.

### 3. Owner acceptance rate (`owner_acceptance`)

- **Unit:** one `assigned` event in `finding_activities` in the window, carrying
  `changes.assignee_id`. Legacy `{}` rows carry no assignee and are skipped.
- **Response window:** from the assignment until the earliest of:
  - the finding's `sla_deadline`;
  - the next assign or unassign on that finding;
  - the finding's resolution.
- **Acted:** the assignee (`actor_type='user'`, `actor_id` = assignee) recorded
  at least one of these inside the response window:
  - `status_changed`, `triage_updated`, `severity_changed`;
  - `comment_added`, `remediation_updated`;
  - `resolved`, `verified`;
  - `false_positive_marked`, `duplicate_marked`;
  - `approval_requested`.
- **Classification:**

  | Class | Condition |
  |---|---|
  | accepted | acted within the window |
  | missed | did not act, and the SLA deadline passed with the assignee still responsible |
  | pending | did not act, and the SLA deadline is in the future (undecided, so left out of the rate) |
  | excluded | the finding has no SLA deadline; or it was assigned after the deadline had passed; or the assignee was reassigned, unassigned or pre-empted by a resolution before the deadline |

- `rate_pct = accepted / (accepted + missed) × 100`. It is `null` when nothing
  has been decided yet.

### Not computed: time to break an attack path

The platform has no data for this, so it is not reported. Here is why:

- Attack paths and exposure chains are computed on demand from the current asset
  graph (`internal/app/attack/exposure_chains.go`) and never persisted.
- Only the demo seeder writes to `attack_paths`.
- Neither asset exposure nor asset relationships keep a change history.

With no record of when a path opened or when one of its links was broken, any
"time to break" figure would be invented. To add it, the platform would first
have to snapshot the chains, for example with the risk-snapshot job, and then
measure how long each chain existed.

## Query plans

Checked with `EXPLAIN ANALYZE` on a throwaway database seeded with 100k assets,
400k findings, 120k activities, 20k validation evidence rows and 50k exposure
events across 5 tenants. Every query takes about 5–30 ms, and every lookup uses
an index:

| Metric | Driving scan | Per-row lookups |
|---|---|---|
| MTTD | `idx_assets_stale_check` ∪ `idx_assets_internet` | `idx_asset_state_history_asset_time`, `idx_exposure_events_asset`, `idx_findings_tenant_asset_status` |
| MTTR validated | `idx_validation_evidence_tenant_created` hash-joined to findings (`idx_findings_resolved_at` ∧ `idx_findings_dashboard`) | none |
| Owner acceptance | `idx_finding_activities_tenant_created` ∧ `idx_finding_activities_type` | `idx_finding_activities_tenant_finding`, `idx_findings_tenant_id_pk` |

The CTE that the aggregates read several times is marked `MATERIALIZED`.
Without it, Postgres inlined the CTE and repeated the correlated lookups once
for each aggregate, which cost 4–8 times as many index probes.

This change needs no migration.
