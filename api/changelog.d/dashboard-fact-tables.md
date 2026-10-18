### Added: dashboard fact layer (per-asset facts and change marking)

- Migration `002916_dashboard_fact_tables` adds per-asset dashboard facts: `dash_asset_state` (current counts by
  state lens, severity, priority, SLA state, source, KEV, reachability, age band and pentest campaign),
  `dash_asset_day` (daily opened, fixed, dispositioned, reopened, net open change, fixed within SLA and fix-time
  histogram; monthly partitions) and `dash_asset_rank` (top 10 open P0-P2 findings per asset and list kind).
  Pentest draft and in-review findings are never stored; pentest findings keep their campaign id so reads can
  apply the campaign rule. Facts hold ids only and are deleted with the tenant.
- Triggers on `findings`, `assets`, `asset_group_members` and `asset_owners` mark the changed asset in
  `dash_dirty_assets` (statement triggers: one small insert per statement and changed asset; re-sightings mark
  nothing). `dash_recompute_asset` and the batched `dash_rebuild_tenant_batch` compute the facts.
- No endpoint reads the facts yet, and the migration computes none: the facts maintainer that builds and
  refreshes them ships separately.
- **Upgrade note:** no action. The migration creates tables, functions and triggers only (no rewrite, no
  backfill, no long lock). The fact tables will use about 2-5 % of the findings table size once built.
