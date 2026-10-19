# Database Implementation Notes

This document contains important notes about database schema design decisions and implementation details that developers should be aware of.

## Assets Table

### finding_count - Dynamically Calculated Field

**IMPORTANT:** `finding_count` is NOT a column in the `assets` table. It is calculated dynamically via a subquery when reading assets.

**Location:** `internal/infra/postgres/asset_repository.go` - `selectQuery()` function

```sql
SELECT
    a.id, a.tenant_id, ...
    COALESCE((SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id), 0) as finding_count,
    ...
FROM assets a
```

**Why this design?**
- Ensures finding count is always accurate and up-to-date
- No need to maintain synchronization between findings and assets tables
- Avoids potential data inconsistency issues

**Implications:**
1. The `Asset` entity has a `findingCount` field in memory (for domain logic)
2. Calling `asset.UpdateFindingCount()` only updates the in-memory value
3. The `Update()` repository method does NOT persist `findingCount` to the database
4. When you read an asset, the finding count is always fresh from the database

**Which findings count:** only open findings (`vulnerability.OpenStatusSQL`)
on the default branch. The risk score uses the same counts.

### risk_score, risk_scored_at and asset_risk_queue

`risk_score` is stored, and kept fresh by AFTER triggers on `findings`,
`assets`, `business_unit_assets`, `business_service_assets`,
`business_units` and `business_services` that queue the asset in
`asset_risk_queue` (functions `asset_risk_enqueue_from_rows`,
`asset_risk_enqueue_new_assets`, `asset_risk_enqueue_finding_update`,
`asset_risk_enqueue_asset_row`, `asset_risk_enqueue_business_unit`,
`asset_risk_enqueue_business_service`). The `asset-risk-score` worker
rescores queued assets; `risk_scored_at` is when the stored score was last
computed (NULL = never scored). Never write `risk_score` from a new code path
expecting it to stick: the next rescore replaces it. See
[asset-risk-score.md](asset-risk-score.md).

**Related code:**
- `pkg/domain/asset/entity.go` - `UpdateFindingCount()` method (in-memory only)
- `pkg/domain/asset/entity.go` - `CalculateRiskScore()` uses findingCount for risk calculation
- `internal/infra/postgres/asset_repository.go` - `selectQuery()` calculates it dynamically

### Repository Identifier Normalization

When assets are created from sensors (e.g., semgrep), the identifier format may differ from SCM imports:

| Source | Identifier Format | Example |
|--------|------------------|---------|
| Sensor (semgrep) | `github.com-org/repo` | `github.com-openctem/openctemio/sdk` |
| SCM Import | `org/repo` | `openctemio/sdk` |

**Normalization logic:** `internal/app/asset/service.go` - `findMatchingRepositoryAsset()` / `updateExistingRepositoryAsset()`

The system handles this by:
1. Detecting provider from prefix (e.g., `github.com-` → GitHub)
2. Extracting the path after the prefix
3. Using multiple matching strategies to find existing assets

### Provider Detection

Provider is detected from asset identifier patterns:

| Pattern | Provider |
|---------|----------|
| `github.com-*` or `github.com/*` | GitHub |
| `gitlab.com-*` or `gitlab.com/*` | GitLab |
| `bitbucket.org-*` | Bitbucket |
| `dev.azure.com-*` | Azure DevOps |
| `arn:aws:*` | AWS |
| `/subscriptions/*` | Azure |
| `projects/*` | GCP |

---

## Findings Table

### sensor_id - Traceability Field

- References `sensors(id)` with `ON DELETE SET NULL`
- Tracks which sensor last submitted the finding (the upsert overwrites it; see
  [ADR-004](decisions/004-finding-provenance.md))
- NULL for manual and imported findings

### source - Finding Source Type

Valid values (constraint `chk_findings_source`): `sast`, `dast`, `sca`,
`secret`, `iac`, `container`, `cspm`, `easm`, `va`, `rasp`, `waf`, `siem`,
`manual`, `pentest`, `bug_bounty`, `red_team`, `external`, `threat_intel`,
`vendor`, `sarif`, `api`, and the legacy alias `sca_tool`. `source` is the
**technique**, not the channel (see [ADR-004](decisions/004-finding-provenance.md)).

---

### acceptance_expires_at - End of a Risk Acceptance

Set with the `accepted` status by the approval flow and by accepted-risk
suppression rules; read by the CI gate. Trigger function
`clear_finding_acceptance_expiry()` (trigger
`trg_findings_clear_acceptance_expiry`, `BEFORE INSERT OR UPDATE`) empties it
on any row whose status is not `accepted`. See
[finding-status-lifecycle.md](finding-status-lifecycle.md#risk-acceptance-end).

### sub_status_id - Organization Sub-Status

An organization's label for the finding inside its canonical status
(`lifecycle_sub_statuses`, [RFC-110](../rfcs/RFC-110-tenant-lifecycles.md)).
The composite foreign key `fk_findings_sub_status` on
`(tenant_id, sub_status_id, status)` guarantees it belongs to the finding's own
tenant and current status. Trigger function `findings_settle_sub_status()`
(trigger `trg_findings_sub_status_settle`, `BEFORE INSERT OR UPDATE`, named to
run after the triggers that change the status or the closure reason) drops it
to NULL (the default label) when the status changes without a new choice, or
when the closure reason no longer matches the one the sub-status is bound to;
an explicit mismatching choice is refused. Metrics never read it
(`TestMetricQueriesNeverReadSubStatus`).

Catalog functions: `lifecycle_sub_status_category_guard()` (trigger
`trg_lifecycle_sub_statuses_category`) refuses a change of a sub-status's
tenant, kind, canonical status, closure reason or key;
`lifecycle_scheme_version_guard()` (trigger
`trg_lifecycle_scheme_versions_immutable`) keeps a published or superseded
lifecycle version unchanged.

### row_version - Optimistic Concurrency

Trigger function `findings_bump_row_version()` (trigger
`trg_findings_row_version`, `BEFORE UPDATE`, migration 003113) adds one to
`row_version` on every update of the row, whichever writer runs it. The
full-row write (`FindingRepository.Update`) carries
`AND row_version = <version read>` and is refused with a conflict when the row
moved on. See [finding-row-version.md](finding-row-version.md).

## Finding decision review functions

- `finding_severity_rank(sev text) RETURNS integer` - severity order (critical 4 ... else 0) for comparisons in triggers.
- `flag_single_person_fp_review(p_tenant uuid, p_finding uuid, p_change text, p_evidence jsonb) RETURNS void` -
  raises the `material_change_single_person` review flag (`finding_decision_reviews`) and a `decision_review`
  timeline entry on a false positive whose latest approved decision was one person's (`single_person` or
  `self_approved`). Called by the triggers `trg_findings_single_person_fp_review` (severity raised, KEV added)
  and `trg_finding_evidence_single_person_fp_review` (new evidence). See
  [finding status lifecycle](finding-status-lifecycle.md#false-positive-approval-level).

## Dashboard fact functions

Migration `002916_dashboard_fact_tables`; see [dashboards.md](dashboards.md#fact-layer).

- `dash_recompute_asset(p_tenant uuid, p_asset uuid) RETURNS integer` - recomputes F1 (`dash_asset_state`),
  F2 (`dash_asset_day`) and F3 (`dash_asset_rank`) of one asset from its findings, writing only differences;
  returns the fact rows changed. The all-zero asset id means findings without an asset.
- `dash_rebuild_tenant_batch(p_tenant uuid, p_after uuid, p_limit integer) RETURNS uuid` - one step of a
  tenant rebuild; NULL after the final step. Go: `DashboardFactsRepository.RebuildTenant`.
- `dash_mark_aged_assets(p_tenant uuid, p_since timestamptz, p_until timestamptz) RETURNS integer` - marks
  assets whose open findings crossed an age band.
- `dash_asset_day_ensure_partitions(from_month date, months integer) RETURNS integer` - creates F2 monthly
  partitions.
- Helpers shared by recompute and reads: `dash_finding_lens(text)`, `dash_sla_state(text)`,
  `dash_age_band(text, timestamptz)`, `dash_fix_hours_bucket(double precision)`, `dash_history_start()`.
- Trigger functions: `dash_mark_from_finding_rows`, `dash_mark_from_finding_update`, `dash_mark_from_asset_rows`,
  `dash_mark_asset_update`, `dash_mark_from_member_rows`, and `dash_mark_asset(uuid, uuid, smallint)`.
- Facts maintainer (migration `dashboard_facts_maintainer`, docs/architecture/dashboards.md "Facts maintainer"):
  - `dash_process_dirty(p_tenant uuid, p_limit integer) RETURNS TABLE (claimed, assets, recomputed, changed,
    oldest_marked_at)` - claims up to `p_limit` dirty rows of the tenant (`FOR UPDATE SKIP LOCKED`), recomputes
    assets whose ORed reasons include 1 or 16, deletes exactly the claimed rows; one transaction.
  - `dash_reconcile_asset(p_tenant uuid, p_asset uuid) RETURNS integer` - recomputes one asset and returns the fact
    rows corrected without a pending mark or an unmarked age-band crossing (drift).
  - `dash_fact_run_step(p_tenant uuid, p_limit integer) RETURNS TABLE (done, run_kind, step_drift)` - one resumable
    step of a full run started by setting `dash_fact_status.run_kind`; Go: `DashboardFactsRepository.StartRun`,
    `RunStep`.
  - `dash_asset_day_maintain() RETURNS TABLE (created, dropped, moved)` - `SECURITY DEFINER`, no input: creates the
    next 24 monthly partitions of `dash_asset_day`, drops those ending before `dash_history_start()`; not executable
    by `PUBLIC`.

## Campaign conversion functions

Migration `remediation_campaigns_hold_tasks` (docs/architecture/remediation-campaigns.md, "Conversion"):

- `remediation_campaign_filter_parse(p_filter jsonb) RETURNS (ok, scoped, fix_key, severities, sources, cve_ids,
  finding_ids, asset_id, tool_name, search_pattern)` - a legacy campaign `finding_filter` parsed as the API parsed
  it: `ok` = it parses, `scoped` = it tracks findings (a fix key, a CVE, a finding id, an asset or a tool).
- `remediation_campaigns_to_tasks(p_report_unchanged boolean) RETURNS integer` - turns the open findings each
  running campaign tracks into tasks of the campaign (one finding, one campaign; findings already in a task stay),
  writes the audit rows, task and finding timeline entries and owner notices, and returns how many campaigns it
  reported. Idempotent. Not called by Go: the migration runs it, the contract step runs it once more and drops both
  functions.

## Best Practices

1. **Never add a `finding_count` column** - Keep it calculated dynamically
2. **Use `CalculateRiskScore()`** after modifying data that affects risk (criticality, findings, etc.)
3. **Check the repository matching in `internal/app/asset/service.go`** when adding new SCM provider support
4. **Update migration constraints** when adding new finding source types
6. **Document new DB functions** - Add to this file when creating new PostgreSQL functions in migrations
