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
| Snapshots, the refresher, Refresh now (migration `003260_dashboard_snapshots`) | **Shipped** |
| Widget kit (web): one frame with every widget state, visualizations over the result shapes, validated chart palettes | **Shipped** |
| Dashboard home on `/`: one renderer for stored dashboards, Organization / Mine switcher, scope badge, freshness line, Refresh now, schedule picker | **Shipped** |

The typed widget endpoints read the facts, and `/` renders only stored
dashboards of typed widgets; the built-in CTEM and Classic views are removed.
The older dashboard endpoints (`/dashboard/*`) still aggregate `findings`
directly for the Insights pages; `GET /dashboard/overview` no longer has a web
caller.

## Current figures and history

A figure labelled as current is always live and counted over the viewer's
scope; stored snapshots are only the history behind a trend line.

- `GET /dashboard/executive-summary` returns the open counts by priority class
  (`p0_open` .. `p3_open`, the open lens, their sum is `findings_total`) and
  `scoped`: true when the figures are counted over the viewer's data scope.
  The Insights pages read these.
- `GET /dashboard/risk-trend` reads the daily `risk_snapshots`, which are
  organization-wide. A scoped viewer gets no trend and the web says "Trend not
  available for your scope" instead of zeros. The chart caption names the date
  of the last snapshot.
- "Open findings" has one definition, the open lens (the findings list's
  `state=open`): `GET /findings/stats` returns `open_count` equal to
  `by_state.open`, and the scheduled report uses it.
- Time to remediate is read from one place, `GET /dashboard/mttr-analytics`
  over 90 days (`overall_hours`), on the Executive page.
- A failed read shows an error with Retry on the card it feeds; a figure with
  no denominator (no scannable asset, nothing to validate, no approval
  decided, nothing fixed) shows "—" with the reason (the widget's
  `not_measured` state), never 0, in neutral colours.
- A widget that throws while rendering shows its own error with Retry (a
  per-widget error boundary, `WidgetErrorBoundary`); the rest of the
  dashboard renders.
- A widget with nothing to count in the viewer's scope shows its empty state,
  not a big 0.

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
  `dashboard.settings_updated`, `dashboard.flow_panel_added`,
  `dashboard.flow_panel_undone`. Plain views are not audited.
- **Exposure flow panel (offered once).** Dashboards that existed before the
  exposure flow metric get the panel once, at the top. `user_dashboards.flow_panel_at`
  records the offer: NULL on every existing row (eligible), `now()` on every
  new row (never auto-offered). The web app opens an eligible dashboard it may
  edit, calls `POST /api/v1/me/dashboards/{id}/flow-panels` (organization:
  `POST /api/v1/organization/dashboards/{id}/flow-panels`, needs
  `dashboards:org:manage`) once, and shows "Exposure flow added at the top"
  with Undo (`DELETE .../flow-panels/{widget_id}`). The add is one `UPDATE`
  guarded by `flow_panel_at IS NULL` in the caller's tenant and owner, so a
  second or concurrent call changes nothing (`added: false`). An empty layout
  or one that already holds an `exposure.flow` widget is only marked. Undo
  removes the widget only when it is an `exposure.flow` panel (400 otherwise)
  and never clears `flow_panel_at`, so a removed panel is not added again.
  Both the add and the undo are audited for personal and organization
  dashboards. Someone else's personal dashboard and other tenants' dashboards
  answer 404; an organization dashboard without the manage permission, 403.

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

- The organization management section on `/dashboards` (create, order,
  default, audience).
- Refreshing a person's dashboards soon after their own changes (coalesced,
  counted against the Refresh now budget).

### Key files

- `pkg/domain/dashboard/` — model, kinds, schedule, audience, caps;
  `widget_spec.go` and `metric_catalog.go` (typed widgets)
- `web/src/features/dashboards/api/widget-spec.ts` — spec types, catalog hook, helpers
- `web/src/features/dashboards/components/dashboard-home.tsx` — the `/` page (switcher,
  freshness, actions); `dashboard-view.tsx` and `widget-view.tsx` — the one renderer
  (a frame and error boundary per widget); `api/widget-adapter.ts` — widget results to
  kit shapes and states; `landing.ts` — which dashboard `/` opens; `metrics.ts` — names,
  definitions and units of the catalog metrics (i18n namespace `dashboards`);
  `editor/` — `dashboard-editor.tsx` (grid, keyboard, undo), `widget-gallery.tsx`,
  `widget-config-panel.tsx`, `history.ts`, `layout-ops.ts`, `spec-ops.ts`
- `internal/app/dashboard/widgets/` — widget results, scopes, limits;
  `snapshot.go` (snapshots, Refresh now, refresher);
  `internal/infra/postgres/dashboard_snapshot_repository.go`,
  `internal/infra/controller/dashboard_snapshots.go`,
  `migrations/003260_dashboard_snapshots.up.sql`;
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
  | `coverage.discovery` | ratio: ledger-tracked assets in scope whose every applicable capability succeeded in the coverage window (a failed, timed-out, paused or never-run capability leaves the asset uncovered; scope-blocked rows and the platform DNS checks are not required); nothing tracked is not measured; opens the uncovered assets | none | coverage ledger + `assets` |
  | `exposure.open_by_priority` | time series by priority (P0-P2) | priority or severity | F1 + F2 |
  | `flow.new_vs_fixed` | time series of flows | none | F2 |
  | `fix.time_to_fix` | duration (1: category) | priority or severity | F2 |
  | `fix.next`, `sla.at_risk` | items (ranked findings) | none | F3 |
  | `crown_jewels.exposed` | scalar (assets), preset P0+P1, filter priority only | none | F1 + `assets` |
  | `ctem.loop` | stages (the five CTEM stages) | none | see "CTEM metrics" |
  | `attack_paths.to_crown_jewels` | paths (reachable crown jewels) | none | attack-path scoring + `assets` |
  | `exposure.flow` | flow (sources, funnel, classes, stages, outcomes) | none | F1 + `findings` + receipts, see "Exposure flow and intake" |
  | `ingest.intake` | intake (receipts per source, noise, health) | none | `ingest_receipts`, see "Exposure flow and intake" |
  | `surface.new_assets` | category: assets added in the window by asset type, with the previous window | none | `assets`, see "Attack surface and accepted risk" |
  | `certificates.expiry` | category: certificates expired, or expiring within 7, 8-30 and 31-90 days | none | `assets` |
  | `exceptions.expiring` | category: accepted findings whose acceptance ends within 7, 8-30 days or later | none | `findings` |

- **Shapes and visualizations.** scalar: stat, progress; ratio: progress,
  stat; duration: stat; category: bar, column, table, donut, stat; time
  series: area, line, column, table (a flow: diverging, column, table, never
  an area); matrix: heatmap, table, column; items: list, table; stages: loop, table;
  paths: paths, table; flow: flow, table; intake: intake, table. The first is
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
| `GET /api/v1/me/dashboards/{id}/data` | `dashboard:read` and the dashboard's owner (another person's dashboard is 404) | the caller's own data scope; per-metric permission applies (below) |
| `GET /api/v1/organization/dashboards/{id}/data` | `dashboards:org:view` (403 without), inside the audience (404 outside) | the whole organization |
| `POST /api/v1/me/dashboards/widget-preview` | `dashboard:read` | one spec, the caller's own data scope (400 when the spec would be refused on save) |

A personal read also needs the permission of what a metric counts:
`findings:read` for finding metrics, `assets:read` for asset metrics
(`crown_jewels.exposed`, `coverage.discovery`, `attack_paths.to_crown_jewels`).
A widget the caller may not read comes back `unsupported` with reason
`forbidden` and no figure, also when the figures come from a stored snapshot.
Organization dashboards are organization-wide by design and follow
`dashboards:org:view`.

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
  the tenant, and a finding no longer open is left out. A row carries the finding's EPSS probability (`epss`, 0 to 1) read from
  the same `findings` row; it is omitted when the feed has no score. The `items` value of
  Fix next also carries `total`: the open count of the list the widget opens
  (priority P0 to P2 plus the widget's asset group filter), read with the same
  filter and the same server-built read scope as the rows, so it equals the
  total of the opened Findings list. SLA at risk opens no list of that count
  and sends no `total`.

### CTEM metrics

The CTEM story on the dashboard is three catalog metrics, drawn by the
`loop` and `paths` visualizations and the `stat` of a count. They are
current figures (no time window or comparison) and, like every widget,
computed for the read's scope and stored in the snapshot.

| Stage of `ctem.loop` | Figure | Second figure | Opens | Not measured when |
|---|---|---|---|---|
| Scoping | crown jewels in scope (`assets.is_crown_jewel`) | crown jewels with an open P0/P1 finding | `/assets?is_crown_jewel=true&program_assets=exclude` | never (0 designated is "designate crown jewels") |
| Discovery | % of assets the coverage ledger tracks (`asset_coverage`, a capability that applies) where every applicable capability succeeded in the last 30 days (scope-blocked rows and the platform DNS checks are not required) | assets not covered | `/assets?coverage=uncovered&program_assets=exclude` | the ledger tracks no asset in scope |
| Prioritize | open P0 findings (F1) | open KEV findings (F1) | the findings list of the same filter | never |
| Validate | % of open findings with validation evidence (the Validation overview's coverage) | retests completed in the last 30 days | `/validation` | no open finding in scope |
| Mobilize | % of open findings with an SLA that is not breached (F1) | breached findings | the breached findings list | no open finding has an SLA |

- Each stage has a state (`good`, `warn`, `crit`, `not_measured`):
  coverage shares are good from 80 %, need attention from 40 %; open P0 is
  good at 0, off track from 5; within SLA is good from 90 %, needs attention
  from 70 %. `focus` is the stage with the largest gap (the first off track,
  else the first that needs attention); the web marks it as the current step.
- `crown_jewels.exposed` counts crown jewels with an open finding of the
  filter's priorities (F1 rows of the asset, with the campaign rule). It
  opens the findings of those priorities on crown jewels grouped by asset
  (`asset_crown_jewel=true&group=asset_id`): the number of groups is the
  figure.
  With no crown jewel designated in the read's scope it is `not_measured`
  (`no_crown_jewels`), never a 0 that meets a "0 exposed" target.
- `attack_paths.to_crown_jewels` reads the attack-path scoring (the whole
  organization's relationship graph, cached for 5 minutes per organization
  and API process) and keeps the crown jewels reached from a public entry
  point, or entry points themselves, that are in the read's scope, not
  deleted and not program-only (`VisibleAssets`). It returns the reachable
  count, the designated count (so "none designated" and "none reachable"
  differ) and the top rows (name, type, criticality, number of entry points
  reaching it, depth, path score; at most `limit`, 10). Entry points and
  intermediate hops are never named; the number of entry points reaching a
  crown jewel is the same figure the attack-path page shows the viewer.
  It is `not_measured` when no crown jewel is designated in scope
  (`no_crown_jewels`) and when the organization has no relationship data
  and nothing is reachable (`no_relationship_data`): "none reachable" is
  only a figure when there is something to reach and a graph to reach it
  through.
- The asset list filter `coverage=covered|uncovered` and the findings
  filter `asset_crown_jewel` use the same predicates as these figures, so a
  figure equals its list for the same viewer. Dashboards leave program-only
  assets out; the lists show them unless `program_assets=exclude` (assets).
- Tests: `dashboard_ctem_widgets_db_test.go` (a scoped member, a campaign
  tester, a member without scope rows and an administrator: crown jewels,
  coverage, validation and attack paths outside the scope, program-only
  assets and another tenant's assets never count or show; figures equal the
  asset and findings lists), `internal/app/dashboard/widgets/ctem_test.go`
  (every stage reads the server-built scope, not-measured stages carry no
  value, out-of-scope crown jewels never reach the result).

### Exposure flow and intake

Two catalog metrics carry the dashboard's first screen: where findings come
from, what the platform removed as noise, and where findings went. Both are
read for one window (the spec's range, 30 days by default; no comparison)
and stored in the snapshot like every widget, so opening the dashboard
costs no extra request and no query.

`exposure.flow` (visualization `flow`):

| Part | Figure | Opens |
|---|---|---|
| Actionable | open findings of classes P0 to P3 (F1), by class; the classes sum to it | `/findings?state=open&priority_class=...` |
| Open | every open finding (F1), by severity | `/findings?state=open` (`&severity=`) |
| Past SLA | open findings with a breached SLA (F1) | the breached findings list |
| In progress | findings with status `in_progress` now | `/findings?status=in_progress` |
| Fixed, Accepted, False positive | findings closed with that status in the window (`resolved_at`) | `/findings?status=...&resolved_at_gte=<window start>` |
| Stages | the `ctem.loop` stages, same read | as `ctem.loop` |
| Intake | the `ingest.intake` value (organization reads only) | as below |

`ingest.intake` (visualization `intake`) sums the receipts
([ingest receipts](ingest-receipts.md)) with activity in the window, per
source: the source group (`sensor`, `import`, `connector`, `ci`, the receipt
kind's group) and the tool (`unknown` when the source named none).

- Per source: receipts, received, created, still detected, reopened,
  closed, suppressed, not stored (skipped or failed), the latest receipt
  (time, status, id) and the usual interval (the median time between its
  receipts; three receipts or more).
- Health: `failed` when the latest receipt failed; `stale` when nothing
  came for more than twice the usual interval and at least a day; `ok`
  otherwise. A source with fewer than three receipts is never stale.
- Noise: received splits into new or reopened (created plus reopened:
  the receipt list's New and Reopened totals added), merged into findings
  that exist (the rest after new, reopened and not stored: still detected
  and repeats within a report) and not stored. These three sum to received.
  Suppressed by an approved rule is the part of New that was stored closed
  on arrival (the list's Suppressed total); it is inside New, not a fourth
  part. One definition per label: the intake summary, the noise headline,
  the hero funnel and the source tooltip all use it.
- Funnel: received and new or reopened are the period's flow (received is
  at least new or reopened); actionable is a stock (open findings of
  classes P0 to P3 now), so the hero shows it apart from the flow with the
  caption "open now", never as a third step that can be larger than the
  first.
- False positive: the findings closed as false positive in the window, the
  same figure as the flow's.
- Each source figure opens the receipt list with the same filter
  (`/findings/imports?origin=&tool=&since=`), whose `totals` are computed by
  the same grouping expressions (`receiptOriginSQL`, `receiptToolSQL`), so
  the figure equals the list it opens.

Scope: receipts count findings across the organization and are not
asset-scoped, so the intake is computed only for a read with no data scope
(an organization dashboard, or a personal dashboard of the owner), the same
rule the receipt list uses to show every receipt. Any other personal read
gets the flow without intake (`intake_reason: organization_only`) and the
intake widget is `not_measured` (`organization_only`): never an estimate and
never organization volumes. No source sent anything in the window:
`no_receipts`.

Tests: `dashboard_flow_widgets_db_test.go` (organization read: sources,
health, noise, another tenant's receipts and receipts outside the window
never count, each source figure equals the receipt list's totals, each
findings figure equals the findings list; personal reads: a scoped member,
a member without scope rows and the owner, the out-of-scope false positive
never counts, receipts only for the owner; receipt list filters refuse
malformed values), `internal/app/dashboard/widgets/flow_test.go`.

### Story widgets: levers, weekly brief, KPI strip

Three metrics tell the dashboard's story above the fold. Like every widget
they are computed by the refresher into the snapshot (never on open), read
through `FactReader` with the scope the server built for the read, and carry
the list each figure counts (`drill`, or none where no list has exactly that
total). Code: `internal/app/dashboard/widgets/levers.go`, `brief.go`,
`kpis.go`; web `components/dashboard-kit/story-viz.tsx`.

- **`exposure.levers`** (shape `levers`): at most three actions, each with an
  exact effect (the figure before and after its list is gone), ranked by the
  risk points they clear (the remediation formula, P0 8, P1 4, P2 2, P3 1,
  severity for unclassified findings):
  - `kev_open`: open KEV findings; effect on P0-P1 open (or on KEV open when
    none of them is P0-P1);
  - `sla_breached`: open P0-P1 findings past their SLA; effect on within SLA,
    `num / (den - n)`;
  - `one_fix`: the proposed remediation suggestion that clears the most risk
    points over its members that are open and in the read's scope
    (`FactReader.TopFix`, `dashboard_levers_repository.go`); pentest findings
    are never counted, so a fix found only on pentest findings never reaches
    a reader outside the campaign; effect on P0-P1 open;
  - `blind_spot`: tracked assets with no successful run in the coverage
    window; it takes the last slot while coverage is under 90 % (unmeasured is
    not safe) and never competes on points.
  Cards carry kind and numbers only (plus a one-fix suggestion title); the web
  words them from translated templates. No asset names are shown.
- **`brief.weekly`** (shape `brief`): up to three deterministic sentences:
  the last seven days' new against fixed findings (F2, chips without a link,
  daily flows are not a list), the first lever, and the P0-P2 findings due soon
  and past their SLA (or the KEV open count when there are none); `quiet` when
  nothing applies. No generated text.
- **`exposure.kpis`** (shape `kpis`, viz `kpi`): P0-P1 open, KEV open, within
  SLA, median time to fix and discovery coverage in one strip, each computed
  by the same code path as its single-figure metric; a figure that cannot be
  measured is `not_measured` with its reason, never 0. Rendered with the
  shared `MetricStrip`.

Permissions on a personal read: the widgets need `findings:read`; without
`assets:read` the parts read from the coverage ledger are removed on the way
out (`maskAssetParts`): the coverage tile becomes `unsupported`/`forbidden`,
the blind spot lever and a brief sentence that words it are dropped.

Tests: `widgets/levers_test.go` (ranking, exact effects, every read uses the
server-built scope, masking), `postgres/dashboard_levers_db_test.go` (TopFix:
data scope, no-scope member, pentest exclusion, dismissed suggestions, cross
tenant).

### Attack surface and accepted risk

Three breakdown metrics (kind `breakdown`, shape `category`, default
visualization `bar`) answer "what changed on our attack surface", "which
certificates need renewing" and "which accepted risks come back soon". Like
every widget they are computed by the refresher into the snapshot, read
through `FactReader` with the scope the server built for the read
(`assetWhere` / `findingWhere`: tenant first, deleted and program-only assets
left out, the data scope, the campaign rule), and each row carries the list
it counts. Code: `internal/app/dashboard/widgets/surface.go`,
`internal/infra/postgres/dashboard_surface_repository.go`.

| Metric | Rows | A row opens | Not measured |
|---|---|---|---|
| `surface.new_assets` (timed, previous period allowed) | one per asset type with an asset added (`created_at`) since the window's first day; with a comparison, also types that had additions only in the previous window (no link) | `/assets?types=<type>&first_seen_after=<first day>&program_assets=exclude` | never; nothing added is the empty state |
| `certificates.expiry` (current) | `expired` (expiry before now), `within_7d`, `within_30d` (after 7 days, before 30), `within_90d` (after 30, before 90); the expiry is the asset list's expiry expression | `/assets?types=certificate&expires_after=...&expires_before=...&program_assets=exclude` (strict bounds, the list's own comparisons) | `no_certificates`: no certificate in scope, never "0 expiring" |
| `exceptions.expiring` (current) | `within_7d` (ends at or before now + 7 days), `within_30d` (after 7, at or before 30), `later`; every acceptance ends (the database caps it), so the bands cover all accepted findings | `/findings?status=accepted&acceptance_expires_at_lte=P7D` (and `_gt` / `_lte` for the others) | never; no accepted risk is the empty state |

- An empty band has no link. The band bounds are taken at the snapshot time;
  a relative findings filter (`P7D`) is evaluated when the list opens, so a
  band equals its list up to the refresh interval.
- Permissions on a personal read: `assets:read` for `surface.new_assets` and
  `certificates.expiry`, `findings:read` for `exceptions.expiring`; without
  it the widget is `unsupported` with reason `forbidden` and no figure, also
  from a stored snapshot.
- Threat model: the rows name asset types and fixed band keys only, never an
  asset or a finding; the counts follow the read's scope, so a scoped member
  never learns how many assets or acceptances exist outside it, and another
  tenant's rows never count (every statement starts with `tenant_id = $1`).
- Tests: `widgets/surface_test.go` (rows, bands, links, not measured, every
  read uses the server-built scope, permission masking),
  `routes/dashboard_surface_widgets_db_test.go` (a scoped member, a member
  without scope rows and an administrator: assets and findings outside the
  scope, program-only certificates and another tenant's rows never count or
  show; every band equals the asset or findings list it opens).

### Empty and unmeasured widgets

One rule for every widget: no figure is drawn until there is something to
count. A findings figure in a scope that has never held a published finding
(any status, the read's asset rule, data scope and campaign rule) is
`not_measured` with reason `no_findings`, never a `0`, an empty chart or a met
target. `FactReader.HasFindings` is read once per dashboard read (a probe in
the read's context) and applies to the counts, ratios (SLA), durations,
series, ranked lists, crown jewels exposed and accepted risks ending. The
exposure flow is not measured only when the scope has no finding and, on an
organization read, no source sent anything; the KPI strip marks its four
findings tiles `no_findings` and keeps the coverage tile (with no tile
measured, the whole strip is `no_findings`); the levers with no lever and
the brief with no lever sentence are `no_findings` too, never "nothing
stands out". Asset, coverage,
certificate and attack path figures never read findings and are unaffected.
Code: `internal/app/dashboard/widgets/empty.go`.

The web routes every "nothing has come in yet" reason (`no_findings`,
`no_tracked_assets`, `no_certificates`, `no_receipts`) and every empty ready
result (no rows, or a series whose every bucket is zero) to the frame's one
compact `no_data_yet` state: "No data yet", the reason, and the next step the
caller may take (Import results or Set up a scan, behind that page's
permission). Such a widget, and a not-measured one, takes one grid row
whatever its stored height, so an empty dashboard never shows tall blank
cards. Other reasons
(`too_few_fixed`, `no_denominator`, `no_crown_jewels`, `organization_only`,
`forbidden`) keep the grey "—" with the reason. Tests:
`widgets/empty_test.go`, `web/src/features/dashboards/__tests__/empty-states.test.tsx`.

The KEV count (`intel.kev_open`) carries its population: `scalar.of` is the
open findings with the widget's filter minus the KEV condition, and
`of_drill` the list it counts, so the stat reads "3 of 40 open" and a 0 is
read correctly.

### Discovery coverage by cause

`coverage.discovery` says why the rest is not covered. `ratio.causes` splits
the uncovered assets (tracked, not covered in the coverage window) by one
cause per asset, read from the ledger rows of the asset with no success in
the window, first match in this order:

| Cause | Ledger row | Who acts |
|---|---|---|
| `no_sensor` | last outcome `not_dispatched` (no eligible sensor took the check) | platform or operator: deploy or widen a sensor |
| `platform_failure` | a platform-side failure: `platform_fail_streak > 0` or a known platform-side outcome (stalled, failed, unfinished, tool error, egress refused, sensor network or proxy fault) | operator: fix the sensor or proxy |
| `paused` | state `paused` | whoever paused it |
| `target_unreachable` | an observation of the target: unreachable, timeout, edge blocked or challenged, rate limited | the organization: the target or what stands in front of it |
| `never_run` | never attempted | wait for the planner, or check its schedule |
| `overdue` | ran before, not within the window | the planner's next run |
| `out_of_scope` | refused by scope policy (`blocked`), only when nothing above applies | the organization's scope |
| `other` | only rows outside the requirement (per-vantage rows, DNS checks) | none |

The outcome lists come from `pkg/domain/coverage` (one source with the
target-versus-platform rule). Each cause row opens
`/assets?coverage=uncovered&coverage_cause=<cause>&program_assets=exclude`;
the asset list filter `coverage_cause` uses the same SQL expression
(`postgres.CoverageCauseCondition`), so a row equals its list, and the causes
sum to the uncovered count. A fully covered share reads no causes. The cause
keys are a closed list (`dashboard.CoverageCauses`, validated by the asset
list input); an unknown key is ignored.

Threat model: the cause rows name fixed keys only, never an asset or a
target; they follow the read's asset scope like the share, so a scoped member
never learns the causes of assets outside it; the cause expression is built
from package constants, and the cause value on the list is a bound parameter.
Tests: `widgets/empty_test.go` (order, links, scope),
`routes/dashboard_empty_coverage_db_test.go` (a scoped member, a member
without scope rows and an administrator: program-only assets and another
tenant's ledger rows never count; each cause equals its asset list; the
causes sum to the uncovered count; no findings is not measured; the KEV
population equals its findings list).

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
- Results are stored per dashboard (see "Snapshots and refresh"): a
  personal snapshot only for its owner and only while their scope is
  unchanged, an organization snapshot for every permitted viewer. Reads are
  bounded: 2 at a time per user, 6 per organization, 12 per API process
  (429 with `Retry-After`), 5 s per statement and 20 s per dashboard.
- A pentest finding without a campaign is stored under the all-f campaign
  id, which matches no membership: like any campaign finding it counts in
  flows and time to fix only for organization-wide and administrator reads
  (F2 has no source column, so the campaign id alone decides).
- Previews are limited per person: a burst of 24, then one every 2 s (per
  API process; 429 with `Retry-After`).
- Tests: `dashboard_widget_data_db_test.go` (figures equal the findings list
  for a scoped member, a campaign tester, a full-data member, a member
  without scope rows and an administrator; another tenant's and unpublished
  findings never show; organization reads, 403 without the permission, 404
  outside the audience and for another person's dashboard; preview refusals;
  measured SLA and time to fix), `internal/app/dashboard/widgets` unit tests.

## Snapshots and refresh

Opening a dashboard reads its stored snapshot (`dash_snapshots`, one row per
dashboard); it does not compute. A snapshot is computed on open only when
there is none, when the layout changed (`layout_hash`), or, for a personal
dashboard, when the owner's scope changed since it was computed
(`scope_key`). The data and preview routes of "Widget data" return the
snapshot with `computed_at`, the effective `refresh_schedule` (the
organization default resolved), `next_refresh_at` (absent for manual or
paused), `stale` (older than twice the schedule, or the last refresh failed)
and `last_refresh_error`.

| Route | Who | Effect |
|---|---|---|
| `POST /api/v1/me/dashboards/{id}/refresh` | `dashboard:read` and the owner (404 for anyone else) | recompute and store now |
| `POST /api/v1/organization/dashboards/{id}/refresh` | `dashboards:org:view` inside the audience | recompute and store now |

- **Refresh now budget**: once a minute per person and dashboard, 30 an hour
  per organization whoever asks (`dash_refresh_requests`; the check and the
  insert run under a per-tenant transaction lock, so concurrent requests
  cannot both pass). Over budget: 429 with `Retry-After`. A refresh that
  took the budget and then found no read slot free gives it back; a
  computation that started and failed (timeout, canceled request) keeps it,
  so a failing dashboard cannot be recomputed faster than the budget.
- **One refresh per dashboard at a time**: Refresh now and the refresher take
  the dashboard's lock (`pg_try_advisory_xact_lock`, held by an open
  transaction until the recompute ends, so a crashed request frees it). A
  Refresh now while another runs answers 429 without using the budget; the
  refresher skips a dashboard that is being refreshed.
- **Refresher** (`dashboard-snapshots` controller, every minute, one replica):
  claims the snapshots whose `next_refresh_at` is due with `FOR UPDATE SKIP
  LOCKED` and a 5-minute lease, recomputes them, and sets the next time from
  the schedule (also written to `user_dashboards.next_refresh_at`). A failure
  keeps the last good snapshot, records `last_error` and retries within 15
  minutes. Manual and paused dashboards are never refreshed on a schedule.
  Refresh-now records older than a day and personal snapshots nobody opened
  for 14 days are pruned (recomputed on the next open).
- **Personal snapshots** are computed for the owner as they are now: in a
  request from the caller's data scope; in the refresher from the owner's
  membership (administrator and owner from the role, scope through
  `datascope.ResolveForStrict`, which fails when the enforcer is not wired).
  An owner who is no longer an active member has the snapshot removed and
  nothing computed on their behalf. A trigger on `tenant_members` deletes a
  member's personal snapshots as soon as the membership is deleted, suspended
  or offboarded (migration `dashboard_snapshots_member_removal`). `scope_key` fingerprints the kind of
  scope, the owner's scope rows (restricted) or the private program assets
  hidden from them (unrestricted), and their pentest campaigns (hashes only);
  a snapshot whose key differs from the owner's current key is never served,
  so a narrowed scope takes effect on the next open. A result computed while
  the scope changed is returned but not stored.
- **Organization snapshots** (`scope_key` `organization`) hold
  organization-wide figures once for every permitted viewer. Their lists keep
  each pentest finding's campaign in the stored data; on every read the rows
  of campaigns the viewer is not a member of are removed (administrators see
  all) and the campaign fields are cleared from the response.
- **Isolation**: a snapshot row carries the tenant and the dashboard; it is
  written only for a dashboard of that tenant (and, personal, of that owner)
  in one statement, and read by tenant and dashboard after the dashboard
  service authorized the caller. Nothing is cached in memory.
- Tests: `dashboard_snapshot_db_test.go` (served from the snapshot until
  Refresh now; per-person and per-organization budget; scope widened and
  narrowed take effect at once; layout change; another person's dashboard
  404; failed refresh shown as stale; one organization snapshot, per-viewer
  campaign rows, no campaign fields in responses; the refresher recomputes
  due snapshots and drops the one of a member who left);
  `dashboard_snapshot_hardening_db_test.go` (one refresh in flight per
  dashboard, refund, preview limit, pentest findings without a campaign in
  the trends); `dashboard_snapshot_migrations_db_test.go` (member removal
  trigger, the all-f campaign id and the rebuild request, up and down).

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
| `dash_ingest_day` | tenant × UTC day × source kind (`sensor`, `import`, `connector`, `ci`) × tool | `reports`, `received`, `created`, `still_detected`, `reopened`, `closed`, `skipped`, `failed`, `suppressed`. Not per asset and not maintained by the facts maintainer: the receipt writer upserts it in the transaction that records each ingest ([ingest-receipts.md](ingest-receipts.md)); kept 13 months; organization-wide only |

What is stored, exactly:

- **Published findings only.** Pentest `draft` and `in_review` findings are
  never stored, and neither are branch-only findings (the lists leave both
  out by default). The lens follows `pkg/domain/vulnerability/finding_lens.go`;
  `dash_finding_lens()` is its SQL form, and a test fails if the two differ.
- **Pentest findings keep their campaign.** For `source = 'pentest'`,
  `pentest_campaign_id` is the campaign (the all-f id
  `ffffffff-ffff-ffff-ffff-ffffffffffff` when the finding has none, which no
  campaign membership matches; migration
  `dashboard_facts_pentest_no_campaign`, which also requested a full
  rebuild); for every other source it is the all-zero id. A viewer-scope read
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
  (`/findings?state=open&sla_status=overdue,exceeded`), validation coverage
  (`/validation`). The Executive P0, P1 and SLA tiles and the Executive
  top-risk rows (the finding) use them. A stored dashboard's widget gets its
  link from the server (`drillHref` in
  `internal/app/dashboard/widgets/compute.go`), built from the widget's own
  filter; a filter the findings list cannot express exactly gives no link
  rather than a link to a wider list.
- A 403 on organization-only figures (`/dashboard/program-metrics`,
  `/ctem-cycles/metrics/trend`) carries
  `details.any_of = ["dashboards:org:view", "dashboards:org:manage"]`. The web
  tells three cases apart (`web/src/lib/api/access-state.ts`): a missing
  permission ("You do not have access", naming the grant, no Retry), a
  switched-off module (`MODULE_NOT_ENABLED`) and a failure (message and
  Retry). The shared `ErrorState` does this for every page; the dashboard's
  CTEM maturity card is left out for a viewer without the grant.

## Dashboard home (web)

`/` renders every stored dashboard with one renderer: each widget of the
layout is drawn from the dashboard's snapshot (`GET …/{id}/data`) in the
widget kit's frame, with its own error boundary.

- **Landing**: the dashboard the viewer last chose (kept in their browser
  while it still exists and they can still read it), else their own default,
  else the organization default, else the first organization dashboard, else
  their first own dashboard. A person with no dashboard at all (none of their
  own, none from the organization) gets a personal copy of the CTEM
  template, created once and computed for their own access, with a hint to
  customize it or choose another template.
- **New layout offer**: a personal copy of the Overview or CTEM template
  (three or more of its `w_ov*` / `w_ct*` widget ids) that lacks some of the
  template's widgets (by metric) shows a hint naming them: "Add them to this
  dashboard" (each missing widget is inserted where the template has it: a
  single figure after its predecessor, a larger widget before its successor;
  every existing widget keeps its place, size and settings, and the layout is
  saved), "Switch to the new layout" (adds a fresh copy of the template under
  a name the person does not already use, e.g. "CTEM (new layout)", and opens
  it; the old dashboard is kept), or dismiss. Nothing changes until the viewer
  chooses; the dismissal is kept in the browser per layout version
  (`LAYOUT_HINT_VERSION` in `layout-hint.ts`). No request is made for the
  hint, and organization dashboards never show it.
- **Templates** are typed widget configs in
  `web/src/features/dashboards/templates.json`. CTEM (the first-visit
  default) and Overview share one set: the exposure flow first (it carries
  the five CTEM stages, so the separate loop widget is no longer in these
  templates), then the figure row (open P0-P1, KEV open, open within SLA,
  time to fix median with p90), discovery coverage beside priority over
  time, new vs fixed, the severity × age heatmap, fix next and attack paths
  to crown jewels; CTEM puts attack paths before fix next and ends with the
  intake and noise reduction panel. Then Executive, Vulnerability program, Triage. `/dashboards` copies one into a personal
  dashboard ("Use template"); the copy is a stored dashboard like any other.
  `api/pkg/domain/dashboard/templates_test.go` parses every template widget
  with the server's spec validation, so a template is never refused on save.
  Names and descriptions are in the `dashboards` i18n namespace.
- **Switcher**: one menu with "Organization" (shown only with
  `dashboards:org:view` or `dashboards:org:manage`; without them the list is
  never requested) and "Mine", search above eight entries, New and Manage.
- **Scope badge**: "Organization-wide" or "Your scope", from the response's
  `scope`; drill-downs open lists in the viewer's own access.
- **Toolbar**: on a phone (below 640px) one row with the switcher filling the
  width, an icon-only Refresh now and an icon-only More menu (44px targets,
  accessible names); Customize and the refresh schedule move into More. From
  640px one row: switcher, Customize, schedule picker, Refresh now, More. The
  dashboard description is hidden on a phone.
- **Freshness line**: one muted line under the toolbar, "Your scope · Updated
  2m ago · Next in 58m" (narrow relative times, full dates on hover); the next refresh
  truncates first on narrow screens; a status line appears under it only when the
  figures are stale, the last refresh failed, or the data is being built for
  the first time. Refresh now answers a 429 with a message. The schedule
  picker is offered to the owner of a personal dashboard or a manager of an
  organization dashboard (the server checks both).
- **Actions**: Customize (personal), Duplicate to mine (organization), Set as
  default (personal; organization for managers), Delete (personal).
- **Customize** (owner of a personal dashboard; `dashboards:org:manage` for
  an organization dashboard, saved through `PUT /organization/dashboards/{id}`):
  - *Add widget* opens the gallery: the catalog by goal (Exposure,
    Remediation and SLA, Threat intel) plus Advanced (Note), searchable by
    name and definition. Each card shows a live preview from
    `POST /me/dashboards/widget-preview`, in the editor's own scope; at most
    12 previews load per opening, lazily as cards scroll into view, and the
    server limits previews per person (burst 24, then one every 2 s).
  - The config panel edits metric, filters (chips per dimension value; KEV
    and reachable as any / yes / no), group-by, time range and comparison
    (not for lists), the visualization (only those valid for the shape, the
    default marked; a change of group-by keeps a visualization that still
    fits), a target for single figures, and the title (empty: the
    translated name). A live preview (debounced) sits on top.
  - The grid: drag by the handle, or focus a widget and use the arrow keys to
    move it, Shift and the arrow keys to resize it (whole columns, 1 to 6
    rows), Enter to configure, D to duplicate and Delete to remove (with
    Undo). Ctrl/Cmd+Z and Ctrl/Cmd+Shift+Z undo and redo within the session;
    every change is announced to screen readers. Save stores the layout;
    Cancel drops the session.
  - Each widget's header holds only the drag handle, the title (truncated,
    full name on hover), Configure and a More menu with Move earlier / later,
    Narrower / Wider, Shorter / Taller, Duplicate and, after a separator,
    Remove (each with its key shown). Duplicate and Remove also show inline
    when the widget itself is at least 22rem wide (a container query on the
    widget, not the viewport). The header never outgrows its widget.
  - On a phone (below 640px) the editor is a single-column list of those
    headers (44px targets), without previews.
  - Moved widgets keep their stored figures; new or changed widgets show
    their preview, or "Figures appear after you save".
- Widget states map from the server: `building` → no data yet, `not_measured`
  and `unsupported` → not measured with the reason, an empty list or series →
  nothing to show, a result without its payload → error; a null figure is
  never drawn as 0. Names, definitions and dimension values are in the
  `dashboards` i18n namespace (en and vi).

### Translation and accessibility checks

- `web/src/features/dashboards/__tests__/i18n-completeness.test.tsx`: every
  `dashboards.*` / `dashboardKit.*` key the dashboard surfaces use exists in
  en and vi; every metric, dimension value, visualization, range, schedule,
  reason and template is named; Vietnamese text is not a copy of the English;
  no display text is hard-coded in the components (JSX text and literal
  `aria-label` / `placeholder` / `title` / `alt`); every template rendered in
  Vietnamese shows no English message.
- `api/pkg/domain/dashboard/templates_test.go`: every catalog metric has a
  name and definition in both web dictionaries; every template widget passes
  the server's spec validation.
- `web/src/features/dashboards/__tests__/a11y.test.tsx`: axe-core on a
  dashboard with every result shape, on the editor and on the gallery
  (colour contrast is left to the browser suite).
- `web/e2e/specs/22-dashboard-home.spec.ts`: `/` at 390 and 1440 px in light
  and dark: widgets render, no horizontal scroll on a phone, no serious or
  critical axe violation inside `main` (chart canvases excluded), a
  screenshot of each combination attached to the report; the editor's
  keyboard move and undo.

## Widget kit (web)

`web/src/components/dashboard-kit/` is what every dashboard widget renders
with (the `/` dashboard and the editor's previews).

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
| `no_data_yet` | the one compact empty state: "No data yet", what will appear and a next-step link (same-origin paths only); one grid row (see "Empty and unmeasured widgets") |
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
`duration`, `category`, `time_series`, `matrix`, `items`, `stages`, `paths`,
`flow`, `intake`. A null
figure means not measured and is never drawn as 0.

| Visualization | Shapes | Notes |
|---|---|---|
| `StatViz` | scalar, ratio, duration | value, change against the previous period with its base ("+15 vs 41 previous period"), a labelled sparkline (first and last bucket's value and date printed under the line, one sentence for screen readers; nothing with fewer than two points), target chip |
| `ProgressViz` | ratio | a meter against the target, with the target tick |
| `BarViz` | category | one bar per key or one stacked bar with shares; values printed |
| `ColumnViz` | time_series (flows) | stacked columns per bucket |
| `AreaLineViz` | time_series (stocks) | stacked area or lines, markers for scoring changes |
| `DivergingViz` | time_series with `opened` / `fixed` | opened up, fixed down, the net in words |
| `HeatmapViz` | matrix | every value printed, shaded on the sequential ramp, with a Fewer-More scale and the maximum; column headers wrap rather than truncate; severity rows carry their severity dot |
| `LoopViz` | stages | the CTEM loop as an ordered list (`<ol>`); each stage's figure and second figure link to their lists, its state is an icon and words in a pill (never a coloured stripe; cards keep one neutral border), unmeasured stages show "—" with the reason; the focus stage is `aria-current="step"` and marked "Act here" with the brand accent (`--brand`, the only use of it) |
| `PathsViz` | paths | reachable crown jewels (linked to the attack paths) and the top ones with the entry points reaching them; "none designated" and "none reachable" are different states |
| `ItemsViz` | items | rows with priority, KEV, asset and due time, and "View all" |
| `ItemsTable` | items (`viz: table`) | the embedded findings table: Priority, Finding (title link, asset line, KEV chip), Severity and SLA columns (Severity and SLA hidden at phone width, the table scrolls sideways), a read-only chip row with the list's filter, the count in the caption, and a footer "Top n of total" with "Open in Findings" |
| `ExposureFlowViz` | flow | sources (with health in words and line style), received to new or reopened to actionable, a labelled ring of actionable findings by priority class (at most four arcs, each a focusable link with a sentence, the largest centred at the bottom, a minimum arc so P0 stays visible; the centre is the count the arcs sum to), the five stages (the focus stage filled with the accent), outcomes (open with its severity split, past SLA, in progress, closed in the period); wires are SVG paths between measured rows, width by volume; below the large breakpoint the columns stack and the wires are dropped |
| `IntakeViz` | intake | the connector panel (each source's icon, tool, receipts, health, count, wired into one summary that shows the hovered source), the noise bar (new or reopened, merged, suppressed, not stored; each legend value opens the receipts), the false-positive row, and the per-source table |

Rules every visualization follows:

- **Change and target are never colour alone.** The change is signed text
  with an arrow and "vs previous period"; its colour comes from the figure's
  polarity (`down_good` for open counts, `up_good` for shares within SLA) and
  a screen reader hears "better" or "worse". The target chip carries an icon
  and words (on target, close to target, off target, not measured).
- **Table view.** Every chart has a "Show table" toggle with the exact figures.
- **Named figure.** A chart is a `role="figure"` named by one sentence: a
  series chart by its first and last bucket and latest values, the diverging
  chart by its net, a bar chart by its largest rows, a heatmap by its peak
  cell. The metric's definition comes from the same registry key as the
  frame's "How this is counted" popover.
- **Phone.** Plots are 180px tall below 640px (220px above). A four-column
  dashboard is two columns on a phone: single-figure tiles (one column, one
  row) sit two abreast and every other widget takes the full row; rows fit
  their content (the stored height applies from 640px). Widget
  titles wrap to two lines, and the per-widget "Updated" footer is hidden
  unless the widget is stale (the dashboard's meta line carries the time).
- **Drill-down.** A mark, row or stage opens its list through a drill builder.
  The path is reduced to a same-origin path (`safeInternalHref`); anything else
  renders as plain text, so a server-supplied path cannot leave the app.
- **One axis, fixed order.** Ordinal keys (severity, priority, age band) keep
  their order; other categories take the categorical slots in their order and
  fold past eight into "Other". Colour follows the entity, never its rank.
- **Motion.** Charts do not animate when the system asks for reduced motion.
- **Connected visuals** (`flow-parts.tsx`, used by the exposure flow and the
  intake): hover, keyboard focus or a first tap lights an element and its
  path and dims the rest to 30 %; a tooltip (`role="tooltip"`, referenced by
  `aria-describedby` while open) gives the title, two or three figures, the
  definition and a link to the same list as the figure; Escape, moving the
  pointer out or moving focus out closes it; the second tap on touch follows
  the link. A healthy source's wire carries a moving dash (static under
  reduced motion); stale is a dotted amber line and failed a dotted red line,
  and the row says so in words.
- **Receipt list.** `/findings/imports` lists the receipts with the filters
  of the figure that opened it (`origin`, `tool`, `since`, removable chips)
  and the API's totals of the filter above the list, so the totals equal
  the dashboard figure.

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
sequential steps with readable ink, the accent band (no data colour at OKLCH
hue 165-200, which belongs to the brand teal that marks where to act), and
that the theme tokens equal the JSON. The dark card surface is the brand's
ink-derived `#0F1D33`.
A unit test (`dashboard-kit/__tests__/palette.test.ts`) runs the same check in
CI. Two documented relaxations, both covered by the table view and labels:
some light-mode marks are below 3:1 against white, and the dark severity
orange and yellow sit above the dark lightness band (a red-orange-yellow
ramp cannot separate inside it), so severity is always labelled and kept in
order.

Key files: `web/src/components/dashboard-kit/`, `web/src/lib/chart-palette.{json,ts}`,
`web/src/lib/format-metric.ts`, `web/scripts/check-palette.mjs`, translations in
`web/src/lib/i18n/dictionaries/{en,vi}/dashboardKit.json`.
