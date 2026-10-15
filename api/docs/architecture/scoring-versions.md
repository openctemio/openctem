# Scoring versions and forward-only recompute

When a scoring model or the settings that feed it change, open findings and
their assets are recomputed **from that moment on**. Closed findings keep the
values they had when they were closed, and history is never rewritten.

Related: [asset risk score](asset-risk-score.md) (the asset model and its
queue), the finding priority classifier
(`internal/app/finding/priority_classification.go`) and the SLA applier
(`internal/app/sla/applier.go`).

## What is computed from a model or settings

| Value | Inputs from settings | Stored version |
|---|---|---|
| Asset `risk_score` | tenant risk scoring settings (preset, factors, bands) | `assets.risk_version` |
| Finding `priority_class` (P0 to P3) | priority rules, ownership floor (`risk_scoring.floor_unowned_at_p2`) | `findings.priority_version` |
| Finding `sla_deadline` | SLA policies (computed in the same pass as the priority) | `findings.priority_version` |

Business unit and asset group roll-ups follow the asset scores. Dashboard
KPIs are live queries over these columns. The CI gate uses severity, KEV and
EPSS only, so it does not depend on a scoring version.

## Versions

`scoring_changes` records every change:

- one **platform** row per model version (`tenant_id` NULL, `source =
  platform_model`), registered at start-up from the constants in
  `pkg/domain/scoring` (`RiskModelVersion`, `PriorityModelVersion`);
- one **tenant** row per change of the risk scoring settings, priority rules
  or SLA policies (`source = risk_settings | priority_rules | sla_policy`).

The row id is the version. The current version of a tenant for a kind is the
newest platform or tenant row (`scoring_version(tenant, kind, model)`). A value
whose stored version is missing or older is **stale**.

- A value is stamped with the version read **before** it is computed, so a
  change that lands during a pass leaves an older stamp and the value is
  computed again. A stamp is never newer than the inputs it was computed with.
- During a rolling deploy, a process running an older model never stamps a
  version at or past a newer platform model row: `scoring_version` stops
  below it. The new model then recomputes the value.
- The asset worker reloads the tenant's risk scoring settings when the
  version is newer than its cached copy, so another replica's change does not
  wait for the cache TTL.

Bumping a model is a code change to the constant: the new row is registered
at start-up, every open finding (or live asset) becomes stale, and the
reconcile queues it. No migration is needed.

## Recording a change

Database triggers (migration `scoring_versions`) record a tenant change and
queue its scope in the same transaction, so no write path can forget it:

| Table | Change that counts | Kind | Queued |
|---|---|---|---|
| `priority_override_rules` | add or delete an active rule; change of class, conditions, active flag or (active) order. A rename does not count | `finding_priority` | assets of the tenant's open findings |
| `sla_policies` | add, delete, any day count, warning percent, default/active flag, asset | `finding_priority` | assets of the tenant's open findings |
| `tenants.settings.risk_scoring` | anything but `floor_unowned_at_p2` | `asset_risk` | every live asset of the tenant (`asset_risk_queue`) |
| `tenants.settings.risk_scoring` | `floor_unowned_at_p2` | `finding_priority` | assets of the tenant's open findings |

Rows of the system tenant (the shared default rules) change only with a
platform model.

## The finding-priority queue

`finding_priority_queue` holds one row per asset whose open findings need a
new priority and SLA deadline. It replaces an in-memory queue that lost its
work on restart and was per replica.

Rows are written by:

- triggers: a new open finding, a reopen, a severity or asset change, an
  asset's criticality, exposure or crown-jewel flag (or restore), business
  unit and business service membership and criticality, and the settings
  triggers above;
- producers: compensating control changes, attribution decisions, AI triage
  verdicts and the threat-intel refresh (`ControlChangePublisher`).

The **finding-priority** worker (`internal/app/reclassify`, every 10 s) claims
up to 200 assets per pass, at most 50 of one tenant, so one tenant's large
backlog cannot starve the others. For each asset it lists the **open**
findings only, re-reads EPSS and KEV from the trusted catalogs, classifies
them, recomputes the SLA deadline, writes the findings that changed and stamps
every computed finding with the version. A failed tenant pass is queued again.

The **finding-priority-reconcile** controller (start-up, then daily, one
replica) queues every asset with a stale finding at once and every other asset
with an open finding ten minutes later, behind event-driven rows. It is the
safety net for inputs no trigger watches (attack-path reachability, the threat
model) and heals a pass that crashed after its claim.

Metrics: `openctem_finding_priority_queue_depth`,
`openctem_finding_priority_queue_oldest_seconds`,
`openctem_finding_priority_checked_total`,
`openctem_finding_priority_changed_total`.

## Forward only

- Open (and reopened) findings are recomputed from the change time.
- Closed findings (`resolved`, `false_positive`, `accepted`, `duplicate`) are
  never listed, classified, given a new deadline or stamped: their class,
  reason, deadline and SLA status stay as they were when they were closed, so
  closed-period metrics (P0 resolved in a period, MTTR per class, SLA met or
  missed) never change after the fact.
- A reopened finding is queued by the reopen trigger and recomputed with the
  current version.

## SLA on a priority change

The SLA applier (`internal/app/sla/applier.go`) computes a finding's first
deadline from detection: `first_detected_at + SLA(class)`. After that,
automatic recomputes only tighten:

| Change | Deadline |
|---|---|
| priority rises (rule, model, KEV, EPSS, asset context) | `min(old, now + SLA(new class))`: the new SLA counts from the change, never a deadline already in the past |
| priority drops | kept; an overdue finding stays overdue |
| SLA policy shortened | `min(old, now + new days)` |
| SLA policy lengthened | kept; new findings use the new policy |
| finding closed | kept as it was when closed |

A deadline that moves later by itself would hide overdue work, so an
extension is an explicit decision (a regression or an expired acceptance
starts a new clock with its own `sla_restarted` entry), never a side effect.
The ingest upsert and the recompute writer (`SavePriorities`) apply the same
rule (`LEAST` of the stored and incoming deadline for an open finding).

The database enforces it for every writer: the BEFORE UPDATE trigger
`trg_findings_sla_deadline_guard` (migration `sla_deadline_guard`) keeps the stored deadline (and the SLA
status for it) when an update would move an open finding's deadline later
or clear it, so a writer holding an older copy of the row (a full-row
update, a recompute that read the row before a tightening) cannot extend it.
Only a transaction marked `SET LOCAL openctem.sla_restart = on` may move it
later: the regression restart (`FindingSLARestartRepository.RestartSLA`) and
the acceptance expiry, which start a new clock on purpose. The promotion of
a branch-only finding (its clock starts when a counting branch first sees
it) is recognised by `branch_only` going from true to false. Closed findings
and a first deadline are not guarded.

Every tightening of an open finding writes a `sla_deadline_tightened`
timeline entry (database trigger, whatever wrote the deadline) with both
deadlines, both classes and the reason (`priority_raised` or
`sla_policy_changed`).

## Preview before apply

Saving risk scoring settings in the console opens a review first:
`POST /tenants/{tenant}/settings/risk-scoring/preview` (team admin,
`settings:write`) runs a dry run over **every** live asset of the
organization with the same engine and inputs the asset-risk-score worker uses
after the change, and nothing is written:

- assets: total, how many scores change (up, down), band moves (from, to,
  count) and the 50 largest changes. Counts cover the whole organization; an
  asset outside the caller's data scope (a private program's asset) is
  counted but never named;
- when `floor_unowned_at_p2` changes, open findings: class moves, deadlines
  that would move earlier (`min(old, now + SLA)`), findings with a linked
  ticket, and manual overrides that keep their class. Closed findings are not
  counted (they never change).

Because it reads the whole organization, the preview is rate limited per
tenant: 6 per minute (token bucket per API replica), then `429` with
`Retry-After` (`internal/infra/http/handler/scoring_preview_limit.go`).

Applying is the existing `PATCH /tenants/{tenant}/settings/risk-scoring`
(section compare-and-swap with `If-Match`), which now also requires **step-up**
re-authentication. It is audited with the before/after diff and the new
`scoring_version`. It does not recompute in the request: the settings trigger
records the change and queues the work, and the response says
`"recompute": "queued"`. The manual "Recalculate" action queues every asset
too (`assets_queued`) instead of rescoring in the request.

Priority rules keep their own dry run (`POST /priority-rules/dry-run`).

## History

Snapshots, trends, MTTR and SLA compliance of past periods are history: they
are never recomputed when a model or settings change.

- `risk_snapshots.risk_version` / `priority_version` record the oldest
  version among the asset scores and open-finding priorities the day's numbers
  came from (NULL = before versions).
- `GET /dashboard/risk-trend` returns, on each point, its versions and the
  scoring changes that took effect there (`scoring_changes`: date, kind,
  source, summary; a day without a snapshot moves the marker to the next
  point). The tenant's own changes and platform model versions are listed,
  never another tenant's.
- The dashboard's priority charts draw a dashed line at each change and say
  "Scoring changed on <date> (<what>): values before and after are not
  directly comparable", so a step is not read as a change in risk.

## No alert storms

A recompute caused by a scoring change (a queue row with a
`scoring_change_id`: the settings triggers, and the reconcile for findings
whose version is stale, such as after a new platform model) does not send one
`finding_priority_escalated` notification per finding. The classification
and its audit entry are unchanged; only the per-finding event is held back.
A move **into P0** is the exception: it still sends its own event, so the
ticket and the workflow a P0 needs start at once (the priority flood guard
still bounds them); the summary counts it too. A P1 move has no separate
escalation setting today, so it is in the summary only.
The worker adds the pass's counts to `scoring_change_impacts` (per tenant and
change: findings checked, changed, raised, raised to P0, lowered, deadlines
moved earlier) and, once no asset of that change is left in the tenant's
queue, sends **one** `scoring_change_applied` notification: "Scoring changed
(<what>): N findings changed priority", with the counts in the body and the
metadata. Its severity follows the most urgent movement (critical when a
finding became P0, high when one rose or a deadline moved earlier), so the
channel's severity filter still applies; the event is on by default and
migration `scoring_change_impacts` turns it on for every channel that already
receives priority escalations. A change that moved nothing sends nothing.
The summary's outbox row is written in the same transaction that marks the
summary notified (`ClaimDrainedSummaries`, one savepoint per summary, rows
locked with `FOR UPDATE SKIP LOCKED`): an enqueue that fails leaves it
pending and the next pass sends it, so a failure never loses a summary.

Recomputes for other reasons (new findings, intel, asset context, controls)
keep their per-finding events and the priority flood guard.

Ticket priority: Jira's priority follows the finding's severity, set when the
ticket is created, so a scoring change updates no ticket and creates none.
If ticket priority ever follows the priority class, it must be a batched
field update under the same summary, never new tickets.

## Security

- Settings are a security control: they decide what is P0 and when work is
  overdue. Changes are made through the settings routes (team admin with
  `settings:write`) and every one leaves a `scoring_changes` row.
- Tenant isolation: queue rows carry `tenant_id` with a composite foreign key
  to the asset; `EnqueueAssets` joins on the tenant's assets, so another
  tenant's asset id is ignored; the worker loads and writes per tenant with
  tenant-scoped queries. Tenant `scoring_changes` rows cascade with the
  tenant; platform rows hold no tenant data.
- Abuse: repeated settings changes coalesce per asset (primary key) and the
  claim is tenant-fair.

## Shipped and planned

Shipped: versions, the durable queue, triggers, the worker and reconcile,
closed findings frozen; SLA deadlines that only tighten, with a timeline
entry; the whole-organization preview and the step-up apply; version stamps
on risk snapshots and markers on trend charts.

Shipped here: one summary notification per scoring change instead of one
per finding.

Planned in the same series: recompute scoped to the CVEs whose EPSS or KEV status
changed.

## Key files

- `migrations/*_scoring_versions.up.sql`
- `pkg/domain/scoring/scoring.go`
- `internal/infra/postgres/scoring_repository.go`
- `internal/app/reclassify/reclassifier.go`, `queue.go`
- `internal/infra/controller/priority_reclassify.go`
- `internal/app/asset/risk_freshness.go` (risk version stamp)
- `internal/app/sla/applier.go`, `migrations/*_sla_deadline_tighten_only.up.sql`
- `internal/app/asset/risk_preview.go`, `internal/app/finding/priority_preview.go`
- `internal/infra/controller/risk_snapshot.go`, `internal/infra/postgres/dashboard_repository.go` (trend markers)
- `web/src/features/organization/components/scoring-impact-dialog.tsx`
- `web/src/features/dashboard/components/ctem/scoring-change-note.tsx`
- `internal/app/finding/scoring_summary.go`, `migrations/*_scoring_change_impacts.up.sql`
- `tests/integration/scoring_versions_test.go`, `tests/integration/sla_tighten_only_test.go`,
  `tests/integration/scoring_preview_test.go`, `tests/integration/scoring_trend_test.go`,
  `tests/integration/scoring_summary_test.go`
