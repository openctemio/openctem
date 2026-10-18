# Dashboards

Who owns a dashboard and how its numbers are produced: the organization and
personal dashboard model, and the stored layer dashboards read from. The
widget registry, snapshots and the refresher build on both and are described
here as they ship.

| Part | Status |
|---|---|
| Ownership: organization and personal dashboards, `dashboards:org:view` / `dashboards:org:manage`, audiences, schedule fields | **Shipped** (migration `002930_dashboard_ownership`) |
| Fact layer: per-asset fact tables, dirty queue, change triggers, recompute and rebuild functions | **Shipped** (migration `002916_dashboard_fact_tables`) |
| Facts maintainer (claims the dirty queue, recomputes, nightly reconciliation, metrics) | Planned |
| Widget registry reading the facts; viewer-scope and organization-wide reads | Planned |
| Snapshots, the refresher, Refresh now | Planned |

Until the maintainer ships, the facts are not read by any endpoint: the
dashboard endpoints still aggregate `findings` directly.

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
- Typed per-widget config schemas and the widget id migration, with the widget
  registry over the fact tables.

### Key files

- `pkg/domain/dashboard/` — model, kinds, schedule, audience, caps
- `internal/app/dashboard/service.go` — authorization, audit, copies, floor
- `internal/infra/postgres/user_dashboard_repository.go` — tenant- and owner-bound queries, audience SQL
- `internal/infra/http/handler/user_dashboard_handler.go`, `internal/infra/http/routes/dashboard.go`
- `migrations/*_dashboard_ownership.up.sql`
- Tests: `internal/infra/http/routes/dashboard_ownership_db_test.go`,
  `tests/integration/migration_dashboard_ownership_test.go`

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
  facts. The maintainer builds each tenant whose `dash_fact_status.rebuilt_at`
  is NULL with `RebuildTenant`, then keeps it current from the queue.
- Disk: about 2-5 % of the findings table size for F1-F3 (estimate: about
  0.1 GB for a 1k-asset tenant, 0.7 GB at 100k assets, 1.5 GB at 1M assets,
  for 10M findings).
- Write cost: measured with `scripts/perf/dashboard_fact_triggers_bench.sql`
  (see the pull request that added the layer for numbers); run it on a
  scratch `*_test` or `*_bench` database only.

### Not done here (the maintainer)

- claim and recompute loop (`dashboard-facts` controller, per-tenant round
  robin, leased), first build of every tenant, nightly reconciliation that
  rebuilds and counts drift, daily `dash_mark_aged_assets`, F2 retention
  (delete days before the window in batches), metrics (fact lag, queue
  depth, drift), an admin "Rebuild dashboard data" action;
- extending the F2 partitions before they run out (a later migration).
