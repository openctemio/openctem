# Safe Deploy & Database Migrations

Canonical, operator-actionable guide for deploying OpenCTEM without a
migration-ordering outage. Read this before any production upgrade.

## TL;DR

- The production API **does not auto-migrate**. On startup it runs a **fail-fast
  schema check** and *refuses to start* if the DB schema is behind the binary.
- Therefore: **apply migrations first, then roll the app.** Never start the new
  binary before its migrations are applied.
- Migrations ship as a **separate, same-versioned image**
  (`ghcr.io/openctemio/migrations:<VERSION>`, released with the API on the same tag).
- Keep `SKIP_SCHEMA_CHECK` **unset** (false) in production — it is the last-line
  safety net.
- Migrations run as the schema owner (`DB_MIGRATE_USER`, `openctem_migrator`);
  the API runs as a DML-only role. See [database-roles.md](database-roles.md).
- Write migrations to be **expand-contract** (backward compatible) so a rolling
  deploy — and a rollback — is always safe. CI blocks destructive migrations.

---

## Why this matters

The prod entrypoint is just `./server` (`Dockerfile` `production` target,
`ENTRYPOINT ["./server"]`). It does **not** apply migrations. Instead,
`cmd/server/main.go` calls `verifySchemaUpToDate` (`cmd/server/schema_check.go`):

- If `schema_migrations.version` is **behind** the highest `migrations/*.up.sql`
  shipped in the binary → the server logs an actionable error and **exits
  non-zero** ("refusing to start").
- If `schema_migrations.dirty = true` (a migration failed midway) → it refuses to
  start until you resolve it.

This converts the *silent, total outage* — every request 500-ing on a
not-yet-created column — into an **obvious, safe refusal**. The cost: if you
start the new binary *before* applying migrations, it crash-loops. The fix is to
guarantee ordering (below), and keep the schema check on as the backstop.

```
        WRONG                                 RIGHT
  build+push new images                 build+push new images (app + migrations,
        │                                     same version)
  roll app ──► schema check fails ──►    apply migrations ──► verify version ──►
  crash-loop (refuses to start)          roll app ──► schema check passes ──► serve
```

---

## The canonical safe-deploy sequence

1. **Build & push both images at the same version.** The release pipeline
   (`.github/workflows/{release,docker-publish}.yml`) builds
   `…/api:<VERSION>` **and** `…/migrations:<VERSION>` from the same commit. Always
   deploy them as a matched pair.

2. **(Recommended) Pre-flight the data.** `scripts/preflight-migrate.sh
   --check-only` runs data-violation checks (e.g. a new `UNIQUE`/`FK` that would
   fail validation against existing rows) *before* touching the schema, so a
   deploy either proceeds cleanly or stops with an actionable message — never
   half-applied. Requires `psql`.

   ```bash
   DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require \
     ./scripts/preflight-migrate.sh --check-only
   ```

3. **Apply migrations and wait for completion.**

   ```bash
   # Local / VM (needs golang-migrate + psql):
   DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require \
     ./scripts/preflight-migrate.sh          # pre-flight, then `migrate up`

   # …or the migrations image directly:
   docker run --rm ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" up
   ```

   - **Kubernetes:** an **init container** (default in `docs/deployment/kubernetes.md`)
     applies migrations before the `api` container starts — ordering is
     guaranteed by Kubernetes with no manual wait. For large/lock-heavy
     migrations use the **pre-deploy `Job`** and
     `kubectl wait --for=condition=complete job/openctem-migrate`.
   - **Docker Compose:** the one-shot `migrate` service in
     `docker-compose.prod.yml` runs first; the `app` service waits on
     `condition: service_completed_successfully`.

4. **Verify the DB version** matches the shipped binary before serving:

   ```bash
   docker run --rm ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" version
   ```

5. **Roll the app.** The schema check now passes and the pods serve. If a pod
   ever comes up before migrations (mis-ordered deploy), it refuses to start —
   loud, not silent.

---

## Expand-contract: how to write deploy-safe migrations

Production is a **rolling deploy**: for a short window, **old app pods run against
the new schema**. A destructive change (dropping/renaming a column, an
incompatible type change, adding a `NOT NULL` column without a default) breaks
those still-running old pods → partial outage. It also makes **rollback unsafe**.

Split every breaking change across **two releases**:

| Release | Step | Example |
|---------|------|---------|
| **N** (expand) | Add the new shape — nullable column / new table / new index. Backward compatible. | `ADD COLUMN email_new TEXT;` backfill; app writes both old + new. |
| **N** (code) | Ship code that stops reading/writing the **old** shape. | Reads prefer `email_new`, dual-writes. |
| **N+1** (contract) | Remove the old shape once nothing running references it. | `DROP COLUMN email_old;` (annotate — see override). |

### Concrete add-then-remove example

Renaming `findings.owner` → `findings.owner_email` safely:

```sql
-- Release N  (000500_add_owner_email.up.sql) — EXPAND, additive, safe.
ALTER TABLE findings ADD COLUMN owner_email TEXT;              -- nullable, no NOT NULL
UPDATE findings SET owner_email = owner WHERE owner_email IS NULL;
-- (App in release N dual-writes owner + owner_email and reads owner_email.)
```

```sql
-- Release N+1 (000771_drop_owner.up.sql) — CONTRACT, destructive but now safe
-- because no running code references `owner` anymore.
-- expand-contract-ok: contract step; `owner` unused since v0.5.0 (replaced by owner_email)
ALTER TABLE findings DROP COLUMN owner;
```

**Rules of thumb**

- Add columns **nullable** (or `NOT NULL DEFAULT …`). Never `ADD COLUMN … NOT NULL`
  without a default, and don't `SET NOT NULL` in the same release you start
  writing the column.
- **Never rename** in place — add-new + backfill + switch reads + drop-old.
- **No in-place `ALTER COLUMN … TYPE`** on a hot column — add a new column of the
  new type, backfill, switch, drop.
- Widening a `CHECK` (adding allowed enum values) is safe; it's a common
  `DROP CONSTRAINT … / ADD CONSTRAINT …` pair and is **not** flagged.
- Build indexes with `CREATE INDEX CONCURRENTLY`; run big index/FK adds in a
  maintenance window (they take long locks — a *lock-duration* risk, not a
  data-compatibility one).

---

## CI guard: `scripts/check-migrations.sh`

A CI job (`Migration Safety` in `.github/workflows/ci.yml`, PRs only) scans the
**new/changed** `migrations/*.up.sql` in a PR and **fails** on deploy-breaking
operations:

| Flagged | Why it breaks a rolling deploy |
|---------|--------------------------------|
| `DROP TABLE` | Old pods still query the table |
| `DROP COLUMN` | Old pods still SELECT/INSERT the column |
| `ALTER COLUMN … TYPE` / `SET DATA TYPE` | In-place type rewrite breaks old pods mid-rollout |
| `RENAME` (column / table / constraint) | Old pods reference the old name |
| `ALTER COLUMN … SET NOT NULL` | Old writes with `NULL` fail |
| `ADD COLUMN … NOT NULL` without `DEFAULT` | Fails on existing rows / old inserts |
| `TRUNCATE` | Destroys data |

It is intentionally low-false-positive: additive changes and CHECK-widening pass.

### Overriding the guard (only for a genuine contract step)

When the destructive change *is* the N+1 contract step (or is otherwise proven
safe), use **either**:

1. **In-file marker** (preferred — self-documenting, travels with the migration):

   ```sql
   -- expand-contract-ok: contract step; column unused since v0.5.0
   ```

   The reason after the colon is **required**.

2. **PR label** `allow-destructive-migration` — wires
   `ALLOW_DESTRUCTIVE_MIGRATION=true` into the CI job.

Run it locally:

```bash
scripts/check-migrations.sh                              # diff vs base branch (CI mode)
scripts/check-migrations.sh migrations/000500_*.up.sql   # scan specific files
```

---

## Dirty-migration recovery

`golang-migrate` runs each migration in a transaction. If a step fails midway,
that step rolls back but `schema_migrations.dirty` is left **true**, and both the
migrator and the app's schema check will refuse to proceed.

Recover:

1. **Find the failed version and inspect** what partially happened:

   ```bash
   docker run --rm ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" version   # prints "<N> (dirty)"
   ```

2. **Fix the root cause.** Usually a **data violation** the migration's new
   constraint/FK/unique-index rejects. `scripts/preflight-migrate.sh --check-only`
   points at the exact offending rows for the known-risky migrations. Clean the
   data.

3. **Force the tracker to the last cleanly-applied version, then re-run:**

   ```bash
   # If version N failed and applied nothing, force to N-1 and re-migrate:
   docker run --rm ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" force <N-1>

   docker run --rm ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" up
   ```

   > `force` only rewrites the version marker — it does **not** run SQL. Point it
   > at a version whose schema actually matches the DB, or you'll desync the
   > tracker from reality. If the failed step *partially* applied DDL outside a
   > transaction, undo those objects by hand first.

`scripts/migrate.sh force <N>` wraps the same command for a local `.env` setup.

---

## Rollback

Because expand-contract migrations are **backward compatible**, rolling the
**app** back to the previous version is safe against the new schema — the old
code doesn't use the new columns, and (in an expand release) the old columns are
still present.

- **Roll the app image back; leave the schema forward.** This is the safe,
  default rollback. The prior binary passes its schema check (its migrations are
  a subset of what's applied — the check only fails when the DB is *behind*, not
  *ahead*).
- **Never auto-roll a destructive (contract) migration `down`.** A `down` that
  re-drops/re-adds columns is itself a breaking change and can lose data. If you
  must revert schema, do it as a new, forward, expand-contract migration.
- If a bad release shipped a **contract** step, prefer fixing forward
  (re-add the removed shape additively) over running `down`.

This is exactly why the CI guard and the expand-contract discipline exist: they
keep *both* the deploy and the rollback boringly safe.

---

## Asset tenant foreign keys (migrations 000920-000922)

Every column that references `assets(id)` from a table with a `tenant_id` also
has a composite foreign key `(tenant_id, <asset column>) → assets(tenant_id, id)`,
so a row of one organization can never point at another organization's asset,
whatever code writes it (research doc 21b, C1/C3/C4 backstop).

| Migration | What it does | Lock |
|---|---|---|
| `000920` | `CREATE UNIQUE INDEX CONCURRENTLY uq_assets_tenant_id_id ON assets (tenant_id, id)` | none on writes |
| `000921` | Pre-flight, then 27 composite keys `NOT VALID` | brief `SHARE ROW EXCLUSIVE`, no table scan |
| `000922` | `VALIDATE CONSTRAINT` on each key | `SHARE UPDATE EXCLUSIVE` (reads and writes continue) |

The single-column keys stay. Each composite key repeats its table's `ON DELETE`
action; `SET NULL` clears only the asset column (`ON DELETE SET NULL (asset_id)`),
never `tenant_id`.

### When 000921 refuses to run

`000921` first counts, per column, rows whose asset belongs to another
organization. If any exist it stops with:

```
cross-tenant asset references found, migration not applied: findings.asset_id: 2, exposure_events.asset_id: 1
```

Nothing is changed (the file is one transaction), but `golang-migrate` marks
version 921 dirty. Existing cross-tenant rows are another organization's data
pointing at an asset, so they are never deleted automatically: decide row by
row with the owner of each organization.

1. List the rows (read-only), replacing the table and column from the error:

   ```sql
   SELECT x.id, x.tenant_id AS row_tenant, a.tenant_id AS asset_tenant, x.asset_id
     FROM findings x JOIN assets a ON a.id = x.asset_id
    WHERE x.tenant_id <> a.tenant_id;
   ```

2. For each row: repoint it to the right asset of its own organization, clear
   the reference where the column is nullable (`exposure_events`,
   `pipeline_runs`, `scan_sessions`, `finding_retests`,
   `runtime_telemetry_events`), or delete the row if it is junk. Keep the
   listing output with the change ticket.
3. `migrate force 920`, then `migrate up` again.

The read-only pre-flight for every column, to run before deploying:
`api/migrations/000921_asset_ref_tenant_fks.up.sql` (the `DO $preflight$`
block) or the query below.

```sql
SELECT ref, n FROM (
    SELECT 'assets.parent_id' AS ref, COUNT(*) AS n FROM assets x JOIN assets a ON a.id = x.parent_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_access_grants.asset_id' AS ref, COUNT(*) AS n FROM asset_access_grants x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_attributions.asset_id' AS ref, COUNT(*) AS n FROM asset_attributions x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_components.asset_id' AS ref, COUNT(*) AS n FROM asset_components x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_identifiers.asset_id' AS ref, COUNT(*) AS n FROM asset_identifiers x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_relationships.source_asset_id' AS ref, COUNT(*) AS n FROM asset_relationships x JOIN assets a ON a.id = x.source_asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_relationships.target_asset_id' AS ref, COUNT(*) AS n FROM asset_relationships x JOIN assets a ON a.id = x.target_asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_services.asset_id' AS ref, COUNT(*) AS n FROM asset_services x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_state_history.asset_id' AS ref, COUNT(*) AS n FROM asset_state_history x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'asset_type_reclassifications.asset_id' AS ref, COUNT(*) AS n FROM asset_type_reclassifications x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'business_service_assets.asset_id' AS ref, COUNT(*) AS n FROM business_service_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'business_unit_assets.asset_id' AS ref, COUNT(*) AS n FROM business_unit_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'easm_dns_check_state.asset_id' AS ref, COUNT(*) AS n FROM easm_dns_check_state x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'easm_evidence.asset_id' AS ref, COUNT(*) AS n FROM easm_evidence x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'exposure_events.asset_id' AS ref, COUNT(*) AS n FROM exposure_events x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'exposures.asset_id' AS ref, COUNT(*) AS n FROM exposures x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'finding_retests.asset_id' AS ref, COUNT(*) AS n FROM finding_retests x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'findings.asset_id' AS ref, COUNT(*) AS n FROM findings x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'pipeline_runs.asset_id' AS ref, COUNT(*) AS n FROM pipeline_runs x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'relationship_suggestions.source_asset_id' AS ref, COUNT(*) AS n FROM relationship_suggestions x JOIN assets a ON a.id = x.source_asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'relationship_suggestions.target_asset_id' AS ref, COUNT(*) AS n FROM relationship_suggestions x JOIN assets a ON a.id = x.target_asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'runtime_telemetry_events.endpoint_asset_id' AS ref, COUNT(*) AS n FROM runtime_telemetry_events x JOIN assets a ON a.id = x.endpoint_asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'scan_coverage_state.asset_id' AS ref, COUNT(*) AS n FROM scan_coverage_state x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'scan_sessions.asset_id' AS ref, COUNT(*) AS n FROM scan_sessions x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'sla_policies.asset_id' AS ref, COUNT(*) AS n FROM sla_policies x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'suppression_rules.asset_id' AS ref, COUNT(*) AS n FROM suppression_rules x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
    UNION ALL SELECT 'user_accessible_assets.asset_id' AS ref, COUNT(*) AS n FROM user_accessible_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
) counts ORDER BY ref;
```

---

## Related

- [Kubernetes Deployment](kubernetes.md) — init-container / pre-deploy-Job manifests
- [Docker Deployment](docker.md) — the one-shot `migrate` compose service
- [Migrations (development)](../development/migrations.md) — authoring migrations
- `scripts/preflight-migrate.sh`, `scripts/migrate.sh`, `scripts/check-migrations.sh`
- `cmd/server/schema_check.go` — the fail-fast schema check + `SKIP_SCHEMA_CHECK`
