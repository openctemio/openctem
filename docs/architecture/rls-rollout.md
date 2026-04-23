# Row-Level Security rollout

## Current state (as of migration 000157)

- **Middleware**: `internal/infra/http/middleware/rls_context.go` sets
  `app.current_tenant_id` (or `app.is_platform_admin`) per request.
- **Policies**: migration `000157_rls_policies_shadow.up.sql` installs
  `<table>_tenant_isolation` policies on the top 20 tenant-scoped
  tables.
- **RLS enabled?**: **No.** Postgres ignores policies on RLS-disabled
  tables, so migration 000157 has zero runtime effect. This is the
  "shadow" state: policies are reviewable + tested but don't change
  behaviour.

## Why shadow-first

Turning on RLS without auditing every read path is the fastest way
to brick production. A single worker/cron that opens a raw
`db.QueryContext(...)` without going through `RLSContextMiddleware`
will see zero rows (fail-closed by design) and start silently
dropping work.

We ship the policies, then ops enables RLS one table at a time once
the target table's read paths have been audited and the integration
suite passes with RLS on for that table.

## How to enable RLS on a single table

1. **Audit call sites**. Grep for `tenant_id` in repo queries for the
   target table. Confirm every caller goes through the tenant
   context — either via `RLSContextMiddleware` on an HTTP route or
   via an explicit `SET LOCAL app.current_tenant_id` inside a
   worker's transaction.
2. **Test with RLS on**. Run the integration suite against a DB where
   the table has `ALTER TABLE <x> ENABLE ROW LEVEL SECURITY` applied.
   Expected: all tests pass.
3. **Write the enable migration**. A new migration that runs only the
   `ALTER TABLE <x> ENABLE ROW LEVEL SECURITY` for that table. Keep
   enables separate so a revert only affects one table.
4. **Deploy + monitor**. Watch `rls_errors` / 5xx / empty-result rate
   for the affected endpoints for at least one full day.

## Policy shape

```sql
CREATE POLICY <table>_tenant_isolation ON <table>
USING (
  tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
  OR current_setting('app.is_platform_admin', true) = 'true'
);
```

Two properties worth understanding:

- `current_setting('x', true)` returns empty when the var is unset
  instead of raising. Combined with `NULLIF(..., '')::uuid`, an unset
  var yields a NULL, which never matches `tenant_id` → **zero rows**
  (fail-closed).
- Platform admin bypass is explicit — `app.is_platform_admin = true`
  is only set by `PlatformAdminRLSMiddleware`, which itself is only
  applied to routes gated by `RequirePlatformAdmin()`.

## Tables covered by shadow-mode policies

| # | Table | Category |
|--:|-------|----------|
| 1 | assets | core |
| 2 | findings | core |
| 3 | exposures | core |
| 4 | finding_comments | core |
| 5 | finding_approvals | core |
| 6 | finding_activity | core |
| 7 | asset_groups | core |
| 8 | asset_relationships | core |
| 9 | components | core |
| 10 | iocs | B6 runtime loop |
| 11 | ioc_matches | B6 runtime loop |
| 12 | runtime_telemetry_events | B6 runtime loop |
| 13 | ctem_cycles | CTEM |
| 14 | priority_class_audit_log | CTEM |
| 15 | compensating_controls | CTEM |
| 16 | scans | scanning |
| 17 | pipelines | scanning |
| 18 | tool_executions | scanning |
| 19 | audit_logs | audit |
| 20 | notification_outbox | notifications |

Remaining ~125 tenant-scoped tables are covered by migration
`000158_rls_policies_shadow_remaining.up.sql` using the same
shadow-mode pattern. Ops enables RLS per table on its own schedule
after validating read-path coverage (see procedure above).
