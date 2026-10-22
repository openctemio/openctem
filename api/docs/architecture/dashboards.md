# Dashboards

Who owns a dashboard and how its numbers are produced: the organization and
personal dashboard model, and the stored layer dashboards read from. The
widget registry, snapshots and the refresher build on both and are described
here as they ship.

| Part | Status |
|---|---|
| Ownership: organization and personal dashboards, `dashboards:org:view` / `dashboards:org:manage`, audiences, schedule fields | **Shipped** (migration `002930_dashboard_ownership`) |
| Fact layer: per-asset fact tables, dirty queue, change triggers, recompute and rebuild functions | **Shipped** (migration `002916_dashboard_fact_tables`) |
| Facts maintainer: queue controller, full runs (first build, requested rebuild, nightly reconciliation with drift count), age bands, F2 partitions and retention, metrics and alerts, "Rebuild dashboard data" | **Shipped** (migration `002963_dashboard_facts_maintainer`) |
| Typed widget spec and metric catalog, server-side validation, `GET /me/dashboards/widget-catalog` | **Shipped** |
| Widget data endpoint reading the facts (personal: viewer scope; organization: whole organization), preview | **Shipped** |
| Snapshots, the refresher, Refresh now | Planned |
| Widget kit (web): one frame with every widget state, visualizations over the result shapes, validated chart palettes | **Shipped** (not yet used by a page) |

The typed widget endpoints read the facts; the older dashboard endpoints
(`/dashboard/*`, used by the built-in views) still aggregate `findings`
directly until the web renders typed widgets everywhere.

## Current figures and history

A figure labelled as current is always live and counted over the viewer's
scope; stored snapshots are only the history behind a trend line.

- `GET /dashboard/executive-summary` returns the open counts by priority class
  (`p0_open` .. `p3_open`, the open lens, their sum is `findings_total`) and
  `scoped`: true when the figures are counted over the viewer's data scope.
  The CTEM view's "Open now" bars read these (each bar opens
  `/findings?state=open&priority_class=Px`); the P0 line and the open-findings
  trend end at the live count.
- `GET /dashboard/risk-trend` reads the daily `risk_snapshots`, which are
  organization-wide. A scoped viewer gets no trend and the web says "Trend not
  available for your scope" instead of zeros. The chart caption names the date
  of the last snapshot.
- "Open findings" has one definition, the open lens (the findings list's
  `state=open`): `GET /findings/stats` returns `open_count` equal to
  `by_state.open`, and the scheduled report uses it.
- Time to remediate is read from one place, `GET /dashboard/mttr-analytics`
  over 90 days (`overall_hours`), on the Classic card and the Executive page.
- A failed read shows an error with Retry on the card it feeds; a figure with
  no denominator (no scannable asset, nothing to validate, no approval
  decided, nothing fixed) shows "—" with the reason, never 0, and its CTEM
  loop stage is neutral grey, never green or amber.
- A card that throws while rendering shows its own error with Retry (a
  per-card error boundary); the rest of the dashboard renders.
- A viewer with no open finding in scope sees "No open findings" and a link to
  scans instead of a big "0 P0".

## Ownership: organization and personal dashboards

Design: [RFC-021](../rfcs/RFC-021-customizable-dashboards.md) (§11 is the ownership model).

Every dashboard is a name, a description, a column count and a widget layout
(at most 40 widgets, at most 4 KB of config per widget). There are two kinds,
stored in one table (`user_dashboards.kind`):

| | Organization | Personal |
|---|---|---|
| Owner | the organization (`user_id` NULL) | one user |
| Numbers | the whole organization | the owner's own data scope |
| Who sees it | holders of `dashboards:org:view`, optionally narrowed to an audience of roles or teams | its owner only |
| Who changes it | holders of `dashboards:org:manage` (owner and admin by default), audited | its owner |
| How many | up to 50, ordered, one may be the organization default | up to 30 per person, one may be the person's default |
| Sharing | the dashboard is the shared view | share = send a copy of the layout; the recipient gets a personal dashboard of their own |

### Shipped

- **Model and API.** Personal dashboards under `/api/v1/me/dashboards`
  (list, create, read, replace, delete, default, schedule, share; create with
  `from_organization_dashboard_id` is "duplicate to mine"). Organization
  dashboards under `/api/v1/organization/dashboards` (list, create, read,
  replace, delete, default, order, audience, schedule).
  Organization defaults under `/api/v1/organization/settings/dashboards`. Gates are listed in
  the [authorization matrix](authorization-matrix.md#dashboards-apiv1medashboards-apiv1organizationdashboards).
- **Permissions.** `dashboards:org:view` replaced `dashboard:aggregate`
  (migration `dashboard_ownership`): every role, template role and API key
  scope holding the old permission holds the new one. The migration writes one
  `role.permission_migrated` audit row per custom role (with its members) and
  one notice to every active owner and administrator of an organization where
  members gained it through a custom role, naming them. `dashboards:org:manage`
  is granted to owner and admin.
- **Full-data grade.** Organization dashboards show organization-wide numbers
  and the names in their lists, so `dashboards:org:view` counts like full data
  access (`permission.IsFullDataGrade`): a role holding it is privileged, an
  outside member holding it needs a second factor at sign-in, and binding such a
  role to a team is owner-only with a recent sign-in.
- **Audience.** `dashboard_audience (tenant_id, dashboard_id, principal_type
  role|group, principal_id)`. No rows: every `dashboards:org:view` holder sees
  the dashboard. With rows, a viewer must hold one of the roles (directly or
  through an active team, `v_user_role_grants`) or be in one of the active teams.
  An audience only narrows: its members still need `dashboards:org:view`.
  Outside the audience the dashboard is left out of the list and is 404 by id,
  so its existence does not leak. Managers see every organization dashboard and
  its audience. Roles and teams must belong to the organization (system roles
  allowed); a deleted role or team simply stops matching (fail closed).
- **Refresh schedule.** `refresh_schedule` is `manual`, `5m`, `15m`, `1h`,
  `6h`, `daily` (with `refresh_daily_minute`, UTC) or NULL for the organization
  default (`settings.dashboards.default_refresh_schedule`, 1h when unset).
  `next_refresh_at` and `paused_at` are kept for the refresher. A schedule is
  refused when it is shorter than the organization's **refresh floor**: the
  limit `dashboard_refresh_floor_minutes` ([limits](limits.md)) when it is set
  and longer than 5 minutes, else 5 minutes. The hosting plan (control plane) or
  the operator (Console > organization limits, or the self-service defaults)
  sets the floor; a floor that cannot be read refuses the change. Managers set
  organization schedules (audited); owners set their personal ones.
- **Copies.** "Duplicate to mine" and "Share layout" copy the name,
  description, columns and widgets into a new personal dashboard (`origin`
  `duplicated` or `shared`, name suffixed " (2)" when taken). No data, schedule,
  audience or default travels with a copy, and the copy is computed for its new
  owner's scope. Sharing needs recipients who are active members of the same
  organization (at most 10 per call, skipped when they already have 30) and is
  audited.
- **Audit.** `dashboard.org_created`, `org_updated`, `org_deleted`,
  `org_default_set`, `org_reordered`, `audience_changed`, `schedule_changed`
  (organization dashboards), `dashboard.layout_shared`,
  `dashboard.settings_updated`. Plain views are not audited.

### Threat model

| Actor | Can | Cannot |
|---|---|---|
| Member without `dashboards:org:view` | their own personal dashboards | list, read or duplicate organization dashboards (403) |
| Org viewer outside an audience | the other organization dashboards | see that the dashboard exists (left out, 404) |
| Org viewer | read and duplicate visible organization dashboards | change any (403) |
| Org manager | every organization dashboard change, audited | read anyone's personal dashboard |
| Colleague / administrator | — | read or change another person's personal dashboard (404: personal queries filter on the owner) |
| Another tenant | — | anything: every query filters on the caller's tenant; an audience entry of another tenant is refused |
| Sharer | send a layout copy to members of the same organization | push data or access, or reach users outside the organization |

Numbers on organization dashboards are computed once for the organization by
the platform, never with a person's access, so nobody's access is borrowed when
a manager leaves.

### Planned

- Stored snapshots, the refresher, Refresh now and refresh after the user's own
  actions (dashboard work package 10). Until then a dashboard's widgets read the
  existing live endpoints, which follow the viewer.
- The grouped switcher (Organization / Mine), scope badge, freshness line and
  schedule picker on `/`, and the organization management section on
  `/dashboards` (work packages 11 and 12).
- Rendering typed widgets on `/` (legacy tiles keep their live rendering
  until then), and serving widget data from stored snapshots.

### Key files

- `pkg/domain/dashboard/` — model, kinds, schedule, audience, caps;
  `widget_spec.go` and `metric_catalog.go` (typed widgets)
- `web/src/features/dashboards/api/widget-spec.ts` — spec types, catalog hook, helpers
- `internal/app/dashboard/widgets/` — widget results, scopes, limits;
  `internal/infra/postgres/dashboard_widget_repository.go` — fact reads;
  `web/src/features/dashboards/api/widget-data.ts` — result types and hooks
- `internal/app/dashboard/service.go` — authorization, audit, copies, floor
- `internal/infra/postgres/user_dashboard_repository.go` — tenant- and owner-bound queries, audience SQL
- `internal/infra/http/handler/user_dashboard_handler.go`, `internal/infra/http/routes/dashboard.go`
- `migrations/*_dashboard_ownership.up.sql`
- Tests: `internal/infra/http/routes/dashboard_ownership_db_test.go`,
  `tests/integration/migration_dashboard_ownership_test.go`

## Widget spec

A widget is a query over the metric catalog plus how to draw it. A typed
widget has `widget_type` `metric` or `note` and a `config` of this form
(stored in the layout, at most 4 KB):

```json
{
  "v": 2,
  "id": "w_7f3a",
  "title": "",
  "data": {
    "kind": "metric",
    "metric": "findings.open",
    "filter": {"severity": ["critical", "high"], "kev": true, "asset_group_id": ["<id>"]},
    "group_by": ["severity"],
    "time": {"range": "inherit", "bucket": "auto", "compare": "previous_period"},
    "limit": 10
  },
  "viz": {"type": "bar", "options": {"orientation": "horizontal", "show_table": false}},
  "target": {"op": "<=", "value": 0},
  "drill": "auto"
}
```

- **Catalog.** `pkg/domain/dashboard/metric_catalog.go` lists every metric,
  the fact dimensions it may be filtered and grouped by, its polarity (which
  direction of a change is good), whether it reads a time window, and the
  result shape per group-by count. The web reads it from
  `GET /api/v1/me/dashboards/widget-catalog` (static, the same for every
  caller, no organization data; any signed-in member).

  | Metric | Shape (no group-by) | Group-by | Facts |
  |---|---|---|---|
  | `findings.open` | scalar (1: category, 2: matrix) | severity, priority, source, SLA state, age band, KEV, reachable | F1 |
  | `exposure.priority_open` | scalar, preset P0+P1 | as above | F1 |
  | `intel.kev_open` | scalar, preset KEV | as above | F1 |
  | `findings.age_bands` | matrix severity × age band | as above | F1 |
  | `sla.within` | ratio | none | F1 |
  | `exposure.open_by_priority` | time series by priority (P0-P2) | priority or severity | F1 + F2 |
  | `flow.new_vs_fixed` | time series of flows | none | F2 |
  | `fix.time_to_fix` | duration (1: category) | priority or severity | F2 |
  | `fix.next`, `sla.at_risk` | items (ranked findings) | none | F3 |

- **Shapes and visualizations.** scalar: stat, progress; ratio: progress,
  stat; duration: stat; category: bar, column, table, donut, stat; time
  series: area, line, column, table (a flow: diverging, column, table, never
  an area); matrix: heatmap, table, column; items: list, table. The first is
  the default; a widget without `viz.type` gets it.
- **Validation** (`ParseWidgetSpec`, on every create, update and copy of a
  personal or organization dashboard): the config is decoded with unknown
  fields refused; the metric must be in the catalog; filter and group-by
  dimensions must be ones the metric allows, with values from their enums
  (severity, priority, source, SLA state, age band); asset group filters are
  ids (at most 10) resolved inside the reader's tenant at read time, so an id
  of another organization matches nothing; the visualization must fit the
  result shape; a target applies only to a single figure; `drill` is `auto`
  or `none` (no URLs); a note takes only text (at most 2,000 characters,
  rendered as sanitized markdown). Widget ids are unique within a dashboard.
  The stored config is the normalized spec, so nothing unvalidated is kept.
- **Legacy tiles.** Any other `widget_type` is a legacy tile drawn by its id;
  its config is never read. `LegacySpec` maps the legacy ids the facts can
  answer (open findings, by severity, past SLA, within SLA, time to fix
  critical, P0 open, KEV) to the equivalent spec for the data endpoint.
- **Threat model.** A widget config is user input stored in a shared layout
  (organization dashboards, shared copies). It can name only catalog metrics,
  fact dimensions and enum values; it carries no SQL, field names outside the
  catalog, URLs or HTML. Tenant and scope are never part of a spec: the data
  endpoint takes them from the caller (personal) or the organization
  (organization dashboards) at read time.

## Widget data

| Route | Who | Numbers |
|---|---|---|
| `GET /api/v1/me/dashboards/{id}/data` | the dashboard's owner (another person's dashboard is 404) | the caller's own data scope |
| `GET /api/v1/organization/dashboards/{id}/data` | `dashboards:org:view` (403 without), inside the audience (404 outside) | the whole organization |
| `POST /api/v1/me/dashboards/widget-preview` | any member | one spec, the caller's own data scope (400 when the spec would be refused on save) |

Every widget of the layout gets a result: typed widgets, and the legacy
tiles the facts can answer (`LegacySpec`); other legacy tiles answer
`unsupported` and keep their live rendering. Each result names its state
(`ready`, `not_measured` with a reason such as `no_denominator` or
`too_few_fixed`, `building` while the organization's first fact build runs,
`unsupported`, `error`), its shape payload, the metric's polarity, the
widget target and whether it is met, and `drill`: the findings list counted
with the same filter (absent when the list cannot express the filter
exactly: age band, "no SLA", KEV or reachable false, several asset groups).
One failing widget never fails the others.

How each figure is computed (`internal/app/dashboard/widgets`,
`internal/infra/postgres/dashboard_widget_repository.go`):

- **Counts** (F1, open lens): the sum of `finding_count`, grouped by up to
  two dimensions. When the filter and group-by use only dimensions the
  history carries (severity, priority, asset group), the previous period is
  the open count at the end of the previous window (open now minus the net
  changes since, from F2) and a scalar gets a sparkline of the open count at
  each bucket end; otherwise `previous_reason` is `previous_not_in_history`.
- **Within SLA** (F1): open findings with an SLA not breached over open
  findings with an SLA; no SLA in scope is `not_measured`, never 0 % or 100 %.
- **Time to fix** (F2): the fix-hours histograms of the days in the window,
  summed; the median and p90 are estimated inside the doubling hour buckets
  (`bucketed: true`); fewer than 5 fixes is `not_measured`.
- **Open by priority over time** (F1 + F2): the open count per key at each
  bucket end (day up to 31 days, week up to 90, month beyond), ending at the
  live count. **New vs fixed** (F2): opened and fixed per bucket, with totals
  for the window and the previous one.
- **Fix next, SLA at risk** (F3): the in-scope partitions' top 10 merged
  (exact for up to 10 rows; only the asset group filter, which does not cut
  into the rank order); list fields are read from `findings` by id inside
  the tenant, and a finding no longer open is left out.

### Scope and isolation

- The tenant comes from the authenticated caller; every statement starts
  with `tenant_id = $1`. Asset group filters resolve inside the tenant.
- **Personal** reads (and previews) use the caller's data scope
  (`datascope.ResolveStrict`: scope rows for a member, hidden private
  program assets for an unrestricted one, nothing for a member without
  scope rows) and the pentest campaign rule for the caller unless they are
  an administrator (an API key never is). A personal dashboard of a holder
  of `dashboards:org:view` still follows their own scope, so its figures
  equal their findings list.
- **Organization** reads compute the whole organization (findings without
  an asset included), pentest findings counted; list rows (finding titles)
  apply the viewer's campaign membership.
- Every read leaves out findings on program-only and soft-deleted assets,
  like every dashboard read.
- Nothing is cached: each read computes for its own caller. Reads are
  bounded: 2 at a time per user, 6 per organization, 12 per API process
  (429 with `Retry-After`), 5 s per statement and 20 s per dashboard.
- Known gap: F2 has no source column, so a pentest finding without a
  campaign (all-zero campaign id) counts in flows and time to fix for every
  viewer; it is never listed and never counted in current figures.
- Tests: `dashboard_widget_data_db_test.go` (figures equal the findings list
  for a scoped member, a campaign tester, a full-data member, a member
  without scope rows and an administrator; another tenant's and unpublished
  findings never show; organization reads, 403 without the permission, 404
  outside the audience and for another person's dashboard; preview refusals;
  measured SLA and time to fix), `internal/app/dashboard/widgets` unit tests.

## Fact layer

### Why per asset

One tenant's members see different asset sets: a restricted member's data
scope is the rows of `user_accessible_assets`, which every list already
filters on. Facts are kept **per asset**, so any scope applies as a join:

- viewer scope: join the facts to the viewer's `user_accessible_assets` rows
  (`(user_id, tenant_id, asset_id)` is the unique index, so the join is
  index-only);
- published scope: the organization, or the members of chosen asset groups;
- the hidden-program rule and soft-deleted assets apply through a join to
  `assets` at read time.

Opening a dashboard then sums a bounded number of fact rows instead of
scanning the findings table.

### Tables

Every table has `tenant_id` first in its key and `REFERENCES tenants ON
DELETE CASCADE`. Facts hold ids only (no names, titles or text). Findings
without an asset are stored under the all-zero asset id
(`00000000-0000-0000-0000-000000000000`), which never matches an asset, an
asset group or a viewer's scope: an organization-wide read includes them, a
scoped read never does (the same rule as the findings list).

| Table | Grain | Columns |
|---|---|---|
| `dash_asset_state` (F1) | asset × dimension combination | `lens` (open, fixed, dispositioned), `severity`, `priority_class` (`none` = unclassified), `sla_state` (ok, warning, breached, none), `source`, `kev`, `reachable`, `age_band` (0-30, 31-60, 61-90, 90+ for open findings, `na` otherwise), `pentest_campaign_id` → `finding_count`, `epss_sum` |
| `dash_asset_day` (F2) | asset × UTC day × severity × priority × `pentest_campaign_id` (as in F1), monthly partitions on `day` | `opened`, `fixed`, `dispositioned`, `reopened`, `net_open_delta`, `fixed_within_sla`, `fix_hours_hist` (12 log2 buckets: under 1 h, 1-2 h, ... 1024 h and more) |
| `dash_asset_rank` (F3) | asset × list kind × partition, top 10 | kinds `fix_next` (priority, severity, newest), `sla_due` (earliest SLA deadline), `oldest` (first detected); `finding_id`, `priority_class`, `severity`, `sort_at` |
| `dash_dirty_assets` | one row per pending mark | `tenant_id`, `asset_id`, `reasons` (bits), `marked_at` |
| `dash_fact_status` | tenant | `rebuilt_at` (last full rebuild, NULL = never built), `aged_marked_at` |

What is stored, exactly:

- **Published findings only.** Pentest `draft` and `in_review` findings are
  never stored, and neither are branch-only findings (the lists leave both
  out by default). The lens follows `pkg/domain/vulnerability/finding_lens.go`;
  `dash_finding_lens()` is its SQL form, and a test fails if the two differ.
- **Pentest findings keep their campaign.** For `source = 'pentest'`,
  `pentest_campaign_id` is the campaign (the all-zero id when the finding has
  none); for every other source it is the all-zero id. A viewer-scope read
  applies the campaign membership rule on it
  (`source <> 'pentest' OR pentest_campaign_id IN <the viewer's campaigns>`),
  and a published read can leave pentest findings out or include them.
- **SLA state** is `findings.sla_status` folded: `on_track` → ok, `warning`
  → warning, `overdue` and `exceeded` → breached, anything else → none. On a
  fixed finding, ok means fixed within the SLA and breached fixed late.
- **Age band** is computed from `first_detected_at` (or `created_at`) when
  the asset is recomputed. Because it moves with time alone,
  `dash_mark_aged_assets` marks the assets whose open findings crossed a
  31, 61 or 91-day boundary since its last run.
- **F2 is derived from finding timestamps**: opened on the day of
  `first_detected_at`, fixed and dispositioned on the day of `resolved_at`,
  reopened on the day of `last_reopened_at`, each with the finding's
  current severity and priority. A closed finding without `resolved_at` is
  counted neither as fixed nor as dispositioned, and leaves the open count on
  the day it was opened, so it never counts as open. With that rule, for
  any scope and day D: open findings at D = open findings now (F1) minus the
  sum of `net_open_delta` after D. The window is the start of the month
  13 months ago onwards (`dash_history_start()`).
- **F3 ranks per partition**: the non-pentest findings of the asset, and
  each pentest campaign separately. A list for a scope merges the in-scope
  partitions' top 10 and is exact for up to 10 rows after the campaign rule
  is applied.

Indexes: the primary keys above; `dash_asset_state (tenant_id, lens,
priority_class) INCLUDE (finding_count)`; `dash_asset_day (tenant_id,
asset_id, day)`; `dash_asset_rank (tenant_id, kind, asset_id, rank)`;
`dash_dirty_assets (tenant_id, asset_id)` and `(tenant_id, id)`.

Row-level security policies exist on all five tables in shadow mode, like the
other tenant tables; isolation is enforced by `tenant_id` in every query.

### Change marking

AFTER triggers append `(tenant_id, asset_id, reasons)` to
`dash_dirty_assets`. No aggregation runs in a trigger.

| Table | Trigger | Reason bit |
|---|---|---|
| `findings` | insert and delete: statement-level over the transition table, one row per distinct asset | 1 |
| `findings` | update: statement-level over the old and new transition tables; marks the findings whose fact inputs changed (status, severity, priority_class, sla_status, sla_deadline, source, is_in_kev, is_reachable, first_detected_at, pentest_campaign_id, asset_id, branch_only, epss_score, resolved_at, last_reopened_at), and the old asset of a moved finding | 1 |
| `assets` | insert, delete, update of asset_type, criticality, status, is_crown_jewel, exposure, is_internet_accessible, deleted_at, program_only, environment | 2 |
| `asset_group_members` | insert, update, delete (statement-level) | 4 |
| `asset_owners` | insert, update, delete (statement-level) | 8 |
| (time) | `dash_mark_aged_assets` | 16 |

A mark never fails the write that caused it. The only constraint a mark can
break is the tenant foreign key, during the cascade of a tenant delete (the
tenant row is already gone in that transaction), so a mark whose tenant no
longer exists is skipped; the cascade removes every fact of the tenant. The
trigger functions have no `EXCEPTION` block, which would open a
subtransaction per statement on the busiest write path.

An asset merge deletes the merged assets' facts and change marks (derived
data) and marks the kept asset, so the facts loop recomputes it from the
findings it received (`mergeDashboardFacts` in
`internal/infra/postgres/asset_merge_plan.go`).

Updates that change no fact input (a re-sighting moving `last_seen_at`)
insert nothing. On `findings` all three triggers are statement-level, so a
bulk change of 10,000 findings on one asset writes one queue row, not
10,000. A row-level update trigger limited to the input columns was measured
as the alternative: free on re-sightings but 11-13 % slower on bulk status
changes, while the statement-level trigger stayed within measurement noise on
every write path. On `assets` the update trigger is row-level with a `WHEN`
clause on the watched columns, because the risk worker updates assets
constantly and those updates must cost nothing.

Reasons 2, 4 and 8 do not change F1-F3 (they hold no asset attributes); they
tell the snapshot refresher that a published asset-group scope or an asset
attribute it groups by changed.

### The dirty queue: no lost marks, no waiting

The queue is append-only with no unique key. A writer adds a row unless an
unclaimed row for the same tenant, asset and reason already exists; it finds
that row with `FOR KEY SHARE SKIP LOCKED` and keeps the lock until it
commits. The maintainer claims rows with `FOR UPDATE SKIP LOCKED`.

- A row the maintainer has claimed is skipped by the writer, which adds a new
  row: the change is picked up on the next pass.
- A row a still-running writer holds is skipped by the maintainer: it is
  claimed only after the writer commits, when its change is visible.
- Writers never block each other (key-share locks are compatible) and never
  wait for the maintainer.

So the queue stays near one row per dirty asset even under bursts, and grows
by at most a few rows per asset when nothing consumes it.

### Recompute and rebuild

| Function | Use |
|---|---|
| `dash_recompute_asset(tenant, asset) → integer` | Recomputes F1, F2 (history window) and F3 of one asset from its findings in one statement, writes only differences, returns the number of fact rows changed (0 when nothing changed). Serialised per asset by a transaction advisory lock; reads and writes only that tenant's rows. |
| `dash_rebuild_tenant_batch(tenant, after, limit) → uuid` | One step of a full rebuild: the next `limit` assets after `after` by id. Returns the last asset id, or NULL after the final step (findings without an asset, removal of facts of assets that no longer exist, `dash_fact_status.rebuilt_at`). |
| `dash_mark_aged_assets(tenant, since, until) → integer` | Marks assets whose open findings crossed an age band in `(since, until]`, records `aged_marked_at`. |
| `dash_asset_day_ensure_partitions(from_month, months) → integer` | Creates F2 monthly partitions (migrations call it; the migrator owns the schema). The first migration creates 13 months back through two years ahead, plus a default partition. |

Go entry point: `internal/infra/postgres/dashboard_facts_repository.go`
(`RecomputeAsset`, `RebuildTenant`, `MarkAgedAssets`). `RebuildTenant`
calls the batch function in a loop, each step its own short transaction, so
a rebuild never holds locks across the tenant and is safe on a live
database; running it again changes nothing.

### Rollout

- The migration only creates tables, functions and triggers; it computes no
  facts. The `dashboard-facts-reconcile` controller builds every tenant whose
  `dash_fact_status.rebuilt_at` is NULL (a resumable first run), and the
  `dashboard-facts` controller keeps it current from the queue.
- Disk: about 2-5 % of the findings table size for F1-F3 (estimate: about
  0.1 GB for a 1k-asset tenant, 0.7 GB at 100k assets, 1.5 GB at 1M assets,
  for 10M findings).
- Write cost: measured with `scripts/perf/dashboard_fact_triggers_bench.sql`
  (see the pull request that added the layer for numbers); run it on a
  scratch `*_test` or `*_bench` database only.

## Facts maintainer

Two leased controllers (`internal/infra/controller/dashboard_facts.go`), each
run by one replica at a time, so a long rebuild never delays the queue.

### Queue: `dashboard-facts` (every 30 s)

- Lists the tenants with change marks and serves them in round-robin from
  the tenant after the one served last, each for at most a 5 s slice within a
  25 s tick: one busy tenant cannot starve the others.
- Each claim is one call of `dash_process_dirty(tenant, 500)`, one
  transaction: it claims the oldest rows with `FOR UPDATE SKIP LOCKED` (never
  a row a running writer or another maintainer holds), ORs the reason bits
  per asset, recomputes the assets whose bits include 1 (findings) or 16 (age
  band), and deletes exactly the claimed ids. Reasons 2, 4 and 8 (asset row,
  group membership, ownership) do not change per-asset facts and are consumed
  without a recompute. A failure rolls the whole claim back: marks stay, facts
  stay.
- Assets are recomputed in id order, as full runs do, so two transactions
  never wait on each other's per-asset locks in a cycle.

### Full runs: `dashboard-facts-reconcile` (every minute, up to 4 minutes a tick)

One run kind at a time per tenant, resumable across ticks (`run_kind`,
`run_cursor`, `run_drift` in `dash_fact_status`), in this order of urgency:

| Kind | When | Drift counted |
|---|---|---|
| in progress | a run that did not finish in the last tick | as its kind |
| `requested` | "Rebuild dashboard data" was asked after the last run started | yes |
| `initial` | the tenant's facts were never built (`rebuilt_at` NULL), e.g. after the upgrade or for a new organization | no (every fact is new) |
| `nightly` | the last run is older than 24 h (spread by when each tenant last ran) | yes |

Each step (`dash_fact_run_step`, 200 assets) calls `dash_reconcile_asset`,
which recomputes the asset and reports the fact rows it corrected as
**drift**, except when the asset had a pending mark (reason 1 or 16) before
or after the recompute (the queue had not reached it yet) or an open finding
of the asset crossed an age band after the later of the last age-band
marking and the last full run (time alone moved it). The final step also
recomputes the findings without an asset and deletes facts of assets that no
longer exist (counted as drift), then records `rebuilt_at`, `reconciled_at`
and `last_drift`. Drift is fixed by the run and counted in
`openctem_dashboard_fact_drift_rows_total{kind}`; any drift is a bug (a write
path that bypassed the triggers, or a recompute error) and raises the
`DashboardFactsDrift` alert.

The same controller, once a day:

- marks crossed age bands per tenant (`dash_mark_aged_assets` from the last
  marking, or the last full run, to now);
- keeps the F2 partitions with `dash_asset_day_maintain()`: creates the next
  24 months and drops the partitions that end before the 13-month history
  window (retention); rows of a month that sat in the default partition are
  deleted and their assets marked, since F2 is derived and the queue writes
  them again into the new partition. The function is `SECURITY DEFINER` (the
  API role has no DDL right), takes no input, runs with `search_path`
  `pg_catalog, pg_temp` and schema-qualified names, waits at most 5 s for a
  lock, and is executable by neither `PUBLIC` nor the console role (see
  [database roles](../deployment/database-roles.md)). It stays in the
  controller rather than in migrations so installations that upgrade rarely
  keep their partitions and retention without a release.

### Metrics and alerts

| Metric | Meaning |
|---|---|
| `openctem_dashboard_fact_lag_seconds` (histogram) | per claimed batch, the age of its oldest mark: write to fact (target p95 < 2 min) |
| `openctem_dashboard_fact_queue_depth` | unprocessed marks, all tenants |
| `openctem_dashboard_fact_queue_oldest_seconds` | age of the oldest unprocessed mark (0 = empty) |
| `openctem_dashboard_fact_drift_rows_total{kind}` | fact rows corrected without a change mark (`requested`, `nightly`) |
| `openctem_dashboard_fact_runs_total{kind}` | completed full runs |

Alerts `DashboardFactsLagging` (oldest mark over 10 minutes for 15 minutes)
and `DashboardFactsDrift` (any drift in a day); runbooks in
`docs/operations/monitoring.md`. No metric carries a tenant label.

### "Rebuild dashboard data"

| Route | Who | Effect |
|---|---|---|
| `GET /api/v1/dashboard-data/` | owner or administrator of the organization | status: `rebuilt_at`, `reconciled_at`, `last_drift`, `rebuild_requested_at`, `running`, `pending`, `queue_depth`, `next_rebuild_at` |
| `POST /api/v1/dashboard-data/rebuild` | owner or administrator | records a rebuild request (202); the reconcile controller runs it as a `requested` run |
| `GET /api/v1/admin/tenants/{tenantId}/dashboard-data` | any console administrator | the same status for one organization |
| `POST /api/v1/admin/tenants/{tenantId}/dashboard-data/rebuild` | console `ops_admin` or `super_admin` | the same request, on the path organization (admin audit `organization.dashboard_data_rebuild`) |

- One accepted request per organization per hour, whoever asks: the check
  and the write are one statement on `dash_fact_status.rebuild_requested_at`,
  so concurrent requests cannot both pass, and the console shares the
  organization's limit. A refused request answers 429 with `Retry-After`.
- Every accepted request writes `dashboard_data.rebuild_requested` to the
  organization's audit log, with `origin` = `organization` or `console`.
- No step-up: the action recomputes derived data and changes no identity,
  privilege or trust (the step-up rule in
  `docs/architecture/step-up-reauth.md` and the console's write inventory).
- Threat model: the tenant comes from the session (or the console path
  organization, after the console checked it exists), never from the body;
  every statement filters on it; the response holds times and counts only.
  The worst a caller with the permission can do is one full recompute of
  their own organization per hour; the run is batched (200 assets per short
  transaction) and time-boxed per tick.

Key files: `migrations/002963_dashboard_facts_maintainer.up.sql`,
`internal/infra/postgres/dashboard_facts_maintainer.go`,
`internal/infra/controller/dashboard_facts.go`,
`internal/app/dashboard/facts/service.go`,
`internal/infra/http/handler/dashboard_facts_handler.go`,
`pkg/domain/dashboardfact/`.

## Drill-downs and refusals

- A figure opens the list built from the filter it is counted with, so the
  list total equals the figure. The targets live in one table,
  `web/src/features/dashboard/lib/drill.ts`: open P0 / P1
  (`/findings?state=open&priority_class=…`), SLA breached
  (`/findings?state=open&sla_status=overdue,exceeded`), open findings in KEV
  (`/findings?state=open&is_in_kev=true`), open findings related to the
  viewer (`/findings?state=open&related_to=me`, the predicate the "Mine"
  widgets count with), validation coverage (`/validation`). A figure whose
  exact list the findings page cannot open yet (EPSS of at least 0.5) is not a
  link rather than a link to a wider list. The CTEM loop, the hero P0 number, the Executive P0, P1 and
  SLA tiles, Executive top-risk rows (the finding) and the custom dashboard
  widgets use them.
- A 403 on organization-only figures (`/dashboard/program-metrics`,
  `/ctem-cycles/metrics/trend`) carries
  `details.any_of = ["dashboards:org:view", "dashboards:org:manage"]`. The web
  tells three cases apart (`web/src/lib/api/access-state.ts`): a missing
  permission ("You do not have access", naming the grant, no Retry), a
  switched-off module (`MODULE_NOT_ENABLED`) and a failure (message and
  Retry). The shared `ErrorState` does this for every page; the dashboard's
  CTEM maturity card is left out for a viewer without the grant.

## Widget kit (web)

`web/src/components/dashboard-kit/` is what every dashboard widget renders
with. No page uses it yet: the dashboard pages move to it together with the
widget data endpoint.

### Frame and states

`WidgetFrame` is a `<section>` labelled by the widget title, with an optional
definition popover ("How this is counted") and a freshness footer ("Updated 5
minutes ago", the absolute time on hover). Each frame is its own React error
boundary: a render error in one widget shows "Couldn't load these figures"
with Retry in that widget, and the rest of the dashboard keeps working.

| State | Shows |
|---|---|
| `loading` | a skeleton shaped like the visualization (stat, chart, list, grid, stages), fixed height |
| `ready` | the figures and the freshness footer |
| `stale` | the figures, "Stale · 2 hr" and Refresh; `isStale()` is true past twice the refresh interval or after a failed refresh |
| `no_data_yet` | what will appear and a next-step link (same-origin paths only) |
| `no_results` | "Nothing matches these filters" and Clear filters |
| `not_measured` | "—" and the reason, grey; never a number and never a good colour |
| `no_access` | the missing permission named from the 403's `details.any_of`, no Retry |
| `module_off` | the module's name and, for administrators, a settings link |
| `error` | "Couldn't load these figures" and Retry for this widget only |
| `partial` | the figures that loaded and a notice naming what is missing |
| `scope_changed` | "Your access changed. Updating these figures." while it recomputes |

`stateFromError()` maps an API error to `no_access`, `module_off` or `error`
with the same rules as the shared error state.

### Result shapes and visualizations

The kit draws the widget result shapes (`types.ts`): `scalar`, `ratio`,
`duration`, `category`, `time_series`, `matrix`, `items`, `stages`. A null
figure means not measured and is never drawn as 0.

| Visualization | Shapes | Notes |
|---|---|---|
| `StatViz` | scalar, ratio, duration | value, change against the previous period, sparkline, target chip |
| `ProgressViz` | ratio | a meter against the target, with the target tick |
| `BarViz` | category | one bar per key or one stacked bar with shares; values printed |
| `ColumnViz` | time_series (flows) | stacked columns per bucket |
| `AreaLineViz` | time_series (stocks) | stacked area or lines, markers for scoring changes |
| `DivergingViz` | time_series with `opened` / `fixed` | opened up, fixed down, the net in words |
| `HeatmapViz` | matrix | every value printed, shaded on the sequential ramp |
| `FunnelViz` | stages | the stage strip; unmeasured stages are grey with their reason |
| `ItemsViz` | items | rows with priority, KEV, asset and due time, and "View all" |

Rules every visualization follows:

- **Change and target are never colour alone.** The change is signed text
  with an arrow and "vs previous period"; its colour comes from the figure's
  polarity (`down_good` for open counts, `up_good` for shares within SLA) and
  a screen reader hears "better" or "worse". The target chip carries an icon
  and words (on target, close to target, off target, not measured).
- **Table view.** Every chart has a "Show table" toggle with the exact figures.
- **Drill-down.** A mark, row or stage opens its list through a drill builder.
  The path is reduced to a same-origin path (`safeInternalHref`); anything else
  renders as plain text, so a server-supplied path cannot leave the app.
- **One axis, fixed order.** Ordinal keys (severity, priority, age band) keep
  their order; other categories take the categorical slots in their order and
  fold past eight into "Other". Colour follows the entity, never its rank.
- **Motion.** Charts do not animate when the system asks for reduced motion.

`web/src/lib/format-metric.ts` formats the figures in the viewer's locale:
grouped counts, compact from 10 000, percentages with one decimal below 10 %,
durations in the largest sensible unit, relative times.

### Chart palettes

`web/src/lib/chart-palette.json` is the source; `src/styles/theme.css`
carries the same values as `--viz-*` tokens for light and dark (each mode has
its own validated steps), and components colour marks with those variables.

| Palette | Use |
|---|---|
| severity (`--viz-sev-*`) | severities and priority classes (P0 = critical colour) |
| categorical (`--viz-cat-1` .. `8`, `--viz-cat-other`) | any other series, in fixed order |
| diverging (`--viz-div-opened`, `--viz-div-fixed`) | flow pairs |
| sequential (`--viz-seq-1` .. `5`, with `--viz-seq-ink-*`) | heatmap shading and the text printed on it |

Status colours (good, warning, critical, unmeasured) stay the semantic
`success` / `warning` / `destructive` / muted tokens and always come with an
icon and a label.

`npm run check:palette` (`web/scripts/check-palette.mjs`) validates every
palette against its mode's card surface: adjacent-pair separation under
protanopia and deuteranopia (OKLab ΔE ≥ 8, 6-8 only with secondary encoding),
normal-vision separation (≥ 15), chroma, lightness band, contrast, monotone
sequential steps with readable ink, and that the theme tokens equal the JSON.
A unit test (`dashboard-kit/__tests__/palette.test.ts`) runs the same check in
CI. Two documented relaxations, both covered by the table view and labels:
some light-mode marks are below 3:1 against white, and the dark severity
orange and yellow sit above the dark lightness band (a red-orange-yellow
ramp cannot separate inside it), so severity is always labelled and kept in
order.

Key files: `web/src/components/dashboard-kit/`, `web/src/lib/chart-palette.{json,ts}`,
`web/src/lib/format-metric.ts`, `web/scripts/check-palette.mjs`, translations in
`web/src/lib/i18n/dictionaries/{en,vi}/dashboardKit.json`.
