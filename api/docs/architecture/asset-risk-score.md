# Asset risk score

Every asset carries a risk score from 0 to 100 (`assets.risk_score`). This
document describes the model and how the score is kept fresh. The model lives
in `pkg/domain/asset/risk_model.go` and `risk_scoring.go`, and is configured
per organization under Settings > Risk scoring
(`GET/PATCH /api/v1/settings/risk-scoring`).

## Model

The default model (`score_composition_mode: likelihood_impact`, preset
`default`) reads risk as likelihood times impact:

```
risk = findings score × exposure factor × criticality factor × (1 − control reduction)
```

**Findings score (0-100).** Only open findings count
(`vulnerability.OpenStatuses`: new, confirmed, in_progress, fix_applied) on the default branch. Resolved, accepted,
false-positive and duplicate findings and unpublished pentest drafts carry no
risk; informational findings add nothing. The asset's `finding_count` and severity counts in the API are
the same population. The worst
severity tier sets the score. The first finding of a tier scores the tier's
base; each further finding of the same tier closes 35% of the gap to the
tier's ceiling, so the score rises with diminishing returns and a tier never
passes its ceiling:

| Tier | First finding | Ceiling | 2 | 5 | 10 |
|---|---|---|---|---|---|
| critical | 70 | 100 | 81 | 95 | 99 |
| high | 50 | 85 | 62 | 79 | 84 |
| medium | 25 | 55 | 36 | 50 | 54 |
| low | 10 | 25 | 15 | 22 | 25 |

So 500 low findings (25) stay below one high (50), and two highs (62) pass
one critical-free medium backlog of any size (55). A finding with an
exploitation signal (in CISA KEV, EPSS at or above 0.5, or a known public
exploit) counts one severity up; an exploitable critical counts twice. The
signals come from the finding row, which threat-intel refreshes update.

**Exposure factor.** The organization's exposure score of the asset's
exposure, read as a percentage. Defaults: public 100, restricted 90,
private 75, isolated 50, unknown 90. An asset whose exposure nobody
established is not assumed to be safe.

**Criticality factor.** The organization's criticality score of the asset's
effective criticality, as a percentage: the highest of its own criticality,
its business units (with parent inheritance), the business services it
powers and the assets it is the control plane of
(`assetdom.EffectiveCriticality`, the rule finding priority uses). A crown
jewel counts as critical; "not rated" counts as medium. Defaults: critical
100, high 90, medium 80, low 60, not rated 80.

**Control reduction.** The strongest active compensating control on the asset
that has not failed its test and has not expired (its reduction factor),
capped at 75%: a control lowers the likelihood, it does not remove the
weakness.

**No open finding means 0.** Exposure and criticality scale risk; they are not
risk on their own.

**Levels.** The organization's risk levels (defaults 80/60/40/20) band the
score into critical, high, medium, low and minimal (1 to the low bound);
0 is "no open risk". The console uses the same bands everywhere.

The weighted models (`multiply`, `amplify_headroom`: weighted sum of exposure,
criticality, findings and data-context points, times an exposure multiplier)
remain available to an organization that chooses them; the industry presets
use them.

**Roll-ups.** Business units and asset groups show the average score of their
assets, and a unit its open and critical finding counts; they are refreshed
after every rescore of a member asset.

### Example

The repository from the original report: 5 critical, 10 high, 59 medium and 7
low open findings, exposure unknown, criticality not rated. Critical tier:
95. Score: 95 × 90% × 80% = 68, high. The same repository marked internet
facing and critical scores 95.

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
| `compensating_control_assets` | insert, delete |
| `compensating_controls` | update of `status`, `test_result`, `reduction_factor`, `expires_at` (the control's assets) |

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

**Saving settings.** `PATCH /settings/risk-scoring` (and the preview) merge the
body into the stored settings: a field or block the body omits keeps its stored
value, so a partial save can never zero the scores. The merged result must pass
the save rules, or the request is refused with 400 and nothing is stored:
component weights sum to 100; every exposure score and every rated-criticality
score is at least 10; exposure scores do not rise as exposure falls (public >=
restricted >= private >= isolated); criticality scores do not rise as
criticality falls (critical >= high >= medium >= low); `unknown` exposure and
`none` criticality are outside the ordering; multipliers 0.1-3.0; risk levels
ordered critical > high > medium > low > 0. The merge happens inside the
settings write, so it follows the section's `If-Match` check and a concurrent
save is not overwritten. A stored value that predates these rules does not
block saving other settings sections; it is refused only when the risk-scoring
section is saved again.

**Settings.** Saving the risk-scoring settings and the manual
`POST /api/v1/settings/risk-scoring/recalculate` rescore the whole
organization at once, as before.

## Explanation

`GET /api/v1/assets/{id}/risk` (permission `assets:read`, the asset's tenant
and data scope; out of scope answers 404) returns the stored score, its level
and freshness, the breakdown of the current model (findings score per tier
with counts and exploitable counts, exposure and criticality factors, the
effective criticality, crown jewel, control reduction) and the five open
findings that drive it, worst first. The breakdown is computed from the
current inputs, so while a rescore is pending it may already show the next
score.

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
