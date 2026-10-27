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

- If any `migrations/*.up.sql` shipped in the binary is **not applied** (missing
  from `schema_migrations_applied`, whatever its version) → the server logs an
  actionable error naming them and **exits non-zero** ("refusing to start").
- If a migration failed midway (the database is dirty) or the database is
  older than the migration baseline → it refuses to start until you resolve it.
- A database **ahead** of the binary (a rollback) is fine.

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

2. **Back up the database.** Every upgrade starts from a backup you have
   restored once (`pg_dump -Fc`, or your provider's snapshot). A database
   older than the migration baseline cannot be upgraded by this release at all:
   see [Migration baseline](#migration-baseline-upgrading-an-older-database).

3. **Apply migrations and wait for completion.**

   ```bash
   # Local / VM (this tree's runner; the password in PGPASSWORD):
   go run ./cmd/openctem-migrate -path migrations -database "$DATABASE_URL" up

   # …or the migrations image directly:
   docker run --rm -e PGPASSWORD ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" up
   ```

   - **Kubernetes:** an **init container** (default in `docs/deployment/kubernetes.md`)
     applies migrations before the `api` container starts — ordering is
     guaranteed by Kubernetes with no manual wait. For large/lock-heavy
     migrations use the **pre-deploy `Job`** and
     `kubectl wait --for=condition=complete job/openctem-migrate`.
   - **Docker Compose:** the one-shot `migrate` service in
     `deploy/docker-compose.yml` runs first; the `api` service waits on
     `condition: service_completed_successfully`.

4. **Verify nothing is pending** before serving:

   ```bash
   docker run --rm -e PGPASSWORD ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" status    # "pending: 0"
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

## Backup, ledger and archive tables

A data migration sometimes keeps the rows it changes in a side table so that
its down migration can put them back (`<thing>_backup_<version>`,
`<thing>_ledger`, `<thing>_archive`, `<thing>_pre_<version>`). Such a table is
rollback data only: once the forward step is final, a later migration drops it
(migration 001481 dropped twelve of them). The pre-upgrade backup is where the
rows live after that.

`tests/unit/migration_ledger_tables_test.go` replays CREATE / RENAME / DROP TABLE
over the migration chain and fails when a table with such a name is left at the
end of it. Either add the drop migration in the same change, or add the table to
`ledgerTableAllowlist` in that test with an expiry date and a reason; when the
date passes the test fails again until the drop migration exists. Temporary
tables (`CREATE TEMP TABLE`) are not counted.

## The migration runner: openctem-migrate

[RFC-130](../rfcs/RFC-130-migration-applied-set.md). The migrations image, the
all-in-one image, the binary install's `openctem-migrate.service` and the
deployment kit all run `openctem-migrate` with the arguments they always
passed (`-path … -database … up`).

- It records every applied migration in `schema_migrations_applied` and applies
  every shipped migration a database lacks, lowest version first. A migration
  merged after a higher-numbered one is applied, not skipped.
- **First run after the upgrade (takeover):** a database the earlier tool
  (golang-migrate) migrated has only `schema_migrations` at version V. The
  runner records every legacy-numbered migration up to V as applied (that tool
  applied all of them) and continues. Nothing to do. If that tool had migrated
  the database past a timestamp version (only possible on a development build
  after this change), the runner refuses and lists those versions, because
  the earlier tool may have skipped some: check each in the schema, record the
  applied ones with `force <version>`, then run `up`.
- From then on `schema_migrations` holds a fence version that no file has, so
  an **older migrations image refuses the database** ("no migration found for
  version 9223372036854775807") instead of migrating it. That is the same as
  before: an older migration job always refused a database a newer release had
  migrated. Roll back the app, not the migration job (see Rollback).
- Two runners never migrate at once: a shared advisory lock (also the earlier
  tool's), polled without blocking inside PostgreSQL.
- The app role can read but never write either table
  (`least-privilege-roles.sql`).

## Dirty-migration recovery

A migration file runs in one implicit transaction (unless it manages its own,
for example `CREATE INDEX CONCURRENTLY`). If it fails, the file rolls back, but
the database is marked **dirty** at its version, and both the runner and the
app's schema check refuse to proceed.

Recover:

1. **Find the failed version and inspect** what partially happened:

   ```bash
   docker run --rm -e PGPASSWORD ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" version   # prints "<V> (dirty)"
   ```

2. **Fix the root cause.** Usually a **data violation** the migration's new
   constraint/FK/unique-index rejects. Find the offending rows with the
   migration's own condition and clean the data. If the file *partially*
   applied DDL outside a transaction, undo those objects by hand.

3. **Clear the flag, then re-run:**

   ```bash
   # V applied nothing (or you undid it): clear the flag, up runs V again
   docker run --rm -e PGPASSWORD ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" force -1
   # V is in fact complete (you finished it by hand): record it instead
   #   … force <V>

   docker run --rm -e PGPASSWORD ghcr.io/openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" up
   ```

   > `force` never runs SQL: it clears the dirty flag and, for `force <V>`,
   > records V as applied. Record a migration only when its changes are really
   > in the database.

`scripts/migrate.sh force <V>` wraps the same command for a local `.env` setup.

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

## Migration baseline: upgrading an older database

The migrations start from one baseline file, `migrations/NNNNNN_baseline.up.sql`
(RFC-053). It holds the schema and built-in rows that every earlier migration
produced, and a fresh database applies it and then the migrations above it.

- A database **at the baseline version or later** (every install that ran the
  last release before the baseline) never runs the baseline and upgrades as
  usual.
- A database **older than the baseline** is refused, and nothing is changed:
  `openctem-migrate` prints what to do, and the API refuses to start with the
  same message. Upgrade in two steps: back up, deploy the last release before
  the baseline (git tag `pre-baseline-NNNNNN`, which still ships every
  migration up to the baseline) and run its migrations, then deploy the new
  release.
- `down` cannot go below the baseline: its down migration refuses and drops
  nothing (the database is then dirty at the baseline's version; `force
  NNNNNN` records it again). Restore a backup instead.

Coming from v0.8.0 (migration 000224): follow
[Upgrading from v0.8.0 to v0.9.0](../operations/upgrade-v0.8-to-v0.9.md#4-database-migration-path),
which gives the exact commands for both steps.

The runbooks of individual migrations that the baseline replaced (for example
the asset tenant foreign keys of 000920-000922 and the assignee scrub of
001012) are in the tree at that tag.

---

## Related

- [Kubernetes Deployment](kubernetes.md) — init-container / pre-deploy-Job manifests
- [Docker Deployment](docker.md) — the one-shot `migrate` compose service
- [Migrations (development)](../development/migrations.md) — authoring migrations
- `scripts/migrate.sh`, `scripts/check-migrations.sh`, `scripts/squash-migrations.sh`
- `cmd/server/schema_check.go` — the fail-fast schema check + `SKIP_SCHEMA_CHECK`

## How CI checks an upgrade

Every night and on every release branch, CI restores the previous release's schema with representative rows, applies
the migrations of the commit about to ship and checks that nothing is pending or dirty, the row counts of the key
tables, that the schema equals a fresh install's and that the API starts
([Upgrade test](../development/ci-cd.md#upgrade-test)). It does not replace your own rehearsal on a copy of
your data: your database has shapes the seed does not.
