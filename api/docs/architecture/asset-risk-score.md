# Asset risk score

Every asset carries a risk score from 0 to 100 (`assets.risk_score`). This
document describes how the score is kept fresh. The formula itself lives in
`pkg/domain/asset/risk_scoring.go` and is configured per organization under
Settings > Risk scoring (`GET/PATCH /api/v1/settings/risk-scoring`).

## Inputs

The score of an asset is computed from:

- its open findings (`vulnerability.OpenStatuses`: new, confirmed,
  in_progress, fix_applied, validated_fixed, not_observed). Resolved,
  accepted, false-positive and duplicate findings and unpublished pentest
  drafts carry no risk. Findings seen only on a feature branch do not count
  either;
- its effective criticality: the highest of its own criticality, its business
  units (with parent inheritance), the business services it powers and the
  assets it is the control plane of (`assetdom.EffectiveCriticality`, the same
  rule finding priority uses);
- its exposure and its data context (internet accessible, PII/PHI, data
  classification, compliance scope);
- the organization's risk-scoring settings.

The same `asset.finding_count` and per-severity counts the API returns are the
ones the score uses.

## Freshness

A score that is not recomputed when its inputs change is worse than no score.
Recomputation is therefore driven by the database, not by each write path:

```
any write path ──► findings / assets / business_* tables
                      │ AFTER triggers (migration asset_risk_queue)
                      ▼
               asset_risk_queue (one row per asset)
                      │ claimed in batches, FOR UPDATE SKIP LOCKED
                      ▼
          asset-risk-score worker ──► per tenant: load, score, store
```

**Triggers.** A row is queued for an asset when:

| Table | Event |
|---|---|
| `findings` | insert, delete (statement level, one row per distinct asset); update of `status`, `severity`, `asset_id` (both assets), `branch_only`, `epss_score`, `is_in_kev`, `exploit_available`, `is_reachable`, `vex_status` |
| `assets` | insert; update of `criticality`, `exposure`, `is_internet_accessible`, `pii_data_exposed`, `phi_data_exposed`, `data_classification`, `compliance_scope`, `is_crown_jewel`; restore of a deleted asset |
| `business_unit_assets`, `business_service_assets` | insert, delete |
| `business_units` | update of `criticality` or `parent_id` (every unit member of the organization) |
| `business_services` | update of `criticality` (the service's assets) |

So CI uploads, sensor ingest, imports, bulk triage, auto-resolve, retests,
threat-intel refreshes that rewrite EPSS or KEV on findings, and manual edits
all rescore the assets they touch, including paths written after this
document.

**Coalescing.** The queue's primary key is the asset: a 100,000-finding import
on one repository queues it once, however many statements the import runs.
The worker rescores it on its next tick, so a long import costs one rescore
per tick, not one per finding.

**Worker.** The `asset-risk-score` controller runs every 10 seconds. It claims
up to 1,000 due rows at a time (oldest first) and keeps claiming until the
queue is empty or 3/4 of the interval is spent. Claimed rows are regrouped per
organization; each group is loaded with a tenant-scoped read, its effective
criticality is resolved in one lookup, and the scores are stored in one
batched, tenant-scoped update. When an organization's rescore fails, its
assets are queued again and the others proceed. Replicas may run the worker
side by side: claims skip locked rows.

**Writes.** A score is stored only when it changed or when the asset was never
scored, and `assets.risk_scored_at` is stamped then. Rescoring an unchanged
asset writes nothing, so the daily reconcile does not touch every asset's
`updated_at`.

**Reconcile.** The `asset-risk-reconcile` controller (one replica, daily and
at start-up) queues every live asset with a due time 10 minutes ahead, behind
rows queued by real changes; a real change pulls the row forward. It covers
inputs no trigger watches (a control-plane relationship, the criticality of
an asset that another asset is the control plane of).

**Settings.** Saving the risk-scoring settings and the manual
`POST /api/v1/settings/risk-scoring/recalculate` rescore the whole
organization at once, as before.

## Freshness in the API

`GET /api/v1/assets` and `GET /api/v1/assets/{id}` return:

- `risk_scored_at`: when the stored score was last computed. Absent means the
  asset was never scored, so `risk_score` is not a real 0.
- `risk_score_pending`: an input changed and the rescore is queued.

## Metrics

| Metric | Meaning |
|---|---|
| `openctem_asset_risk_queue_depth` | assets waiting for a rescore |
| `openctem_asset_risk_queue_oldest_seconds` | age of the oldest due row (alert when it keeps growing) |
| `openctem_asset_risk_rescored_total` | assets rescored |
| `openctem_asset_risk_changed_total` | assets whose stored score changed |
| `openctem_controller_*{controller="asset-risk-score"}` | the usual controller run, duration and error metrics |

## Security

- Every read and write after the claim is tenant-scoped (`tenant_id` from the
  queue row, never from a request). `Enqueue` joins `assets` on the tenant, so
  an id of another organization is never queued. Tests:
  `tests/integration/asset_risk_freshness_test.go`
  (`TestAssetRisk_TenantIsolation`).
- The claim is the only cross-tenant statement (`ClaimForPlatform`); no HTTP
  handler can reach it.
- Both queue foreign keys cascade: deleting an asset or an organization
  removes its rows, and the trigger functions queue only assets that still
  exist.

## Repair

A deployment that adds the queue (migration `asset_risk_queue`) queues every
live asset once; the worker rescores the inventory within minutes of start-up.
To force a full rescore of one organization later, use the Recalculate button
under Settings > Risk scoring.
