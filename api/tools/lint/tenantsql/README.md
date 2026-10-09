# tenantsql: no tenantless by-id statements

Decision D-11. A repository statement such as

```sql
DELETE FROM integrations WHERE id = $1
```

is safe only while every caller checks the tenant first. One handler that
forgets turns it into a cross-tenant IDOR. Every statement that selects,
updates or deletes a row of a **tenant-scoped table** (a base table with a
`tenant_id` column) by its primary key must carry a tenant predicate:

```sql
DELETE FROM integrations WHERE tenant_id = $1 AND id = $2
```

and the tenant comes from the authenticated context (the caller's tenant, or
the sensor key's tenant), never from the request body.

## What the check does

`TestNoNewTenantlessStatements` parses `internal/infra/postgres`, folds the SQL
each function sends to the driver (string literals, package constants,
no-argument query helpers such as `r.selectQuery()`, local variables built
with `:=`/`=`/`+=`, and `fmt.Sprintf` formats), and flags a statement when

1. it is a `SELECT`, `UPDATE`, `DELETE` or `WITH`,
2. its target table is listed in `tenant_tables.txt`,
3. it has an `id = $n` or `id = ANY($n)` predicate on that table, and
4. it has no tenant predicate (`tenant_id = …`, `tenant_id IN …`,
   `tenant_id IS NULL`, `… = x.tenant_id`).

The check is deliberately syntactic. It will not see SQL assembled at run time
from values it cannot fold, and a join condition on `tenant_id` counts as a
tenant predicate. It catches the common shape, the one this code base had
about 150 of.

## When a statement legitimately has no tenant

- **A platform job or controller** (a reaper, a scheduler claim, an outbox
  worker) that works across tenants: give it its own method whose name ends in
  `ForPlatform` or `Unscoped` (or contains `ForPlatformIn…`, `UnscopedIn…`),
  and call it only from that job. The name is the reviewable marker, so it
  needs no allowlist entry. `TestHandlersDoNotCallPlatformMethods` fails if an
  HTTP handler calls one.
- **Anything else** (a row whose tenant is NULL by design, a system catalog
  row): add `file:Func:table  reason` to `allowlist.txt`. The reason must say
  why the id alone is safe.

The allowlist only shrinks: the test also fails on an entry that no longer
matches a statement. Entries marked `D-11 baseline` predate the guard and are
being fixed area by area.

## The table list

`tenant_tables.txt` is generated from the migrated schema.
`TestTenantTablesMatchSchema` runs on the Postgres CI tier and fails when it
drifts. To regenerate against a migrated scratch database whose name ends in
`_test`:

```bash
cd api
DATABASE_URL=postgres://…/openctem_test?sslmode=disable TENANTSQL_UPDATE=1 \
  GOWORK=off go test ./tools/lint/tenantsql -run TestTenantTablesMatchSchema
```

## Run it

```bash
cd api
GOWORK=off go test ./tools/lint/tenantsql/... -count=1
```

`tools/lint/getbyid` is the older, name-based sibling (it flags `GetByID`
methods without a `tenantID` parameter). This check looks at the SQL instead,
so it also covers `Update`, `Delete` and every other method name.
