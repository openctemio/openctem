# Safe Deploy & Database Migrations

Canonical, operator-actionable guide for deploying OpenCTEM without a
migration-ordering outage. Read this before any production upgrade.

## TL;DR

- The production API **does not auto-migrate**. On startup it runs a **fail-fast
  schema check** and *refuses to start* if the DB schema is behind the binary.
- Therefore: **apply migrations first, then roll the app.** Never start the new
  binary before its migrations are applied.
- Migrations ship as a **separate, same-versioned image**
  (`openctemio/migrations:<VERSION>` / `ghcr.io/openctemio/migrations:<VERSION>`).
- Keep `SKIP_SCHEMA_CHECK` **unset** (false) in production — it is the last-line
  safety net.
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
   docker run --rm openctemio/migrations:<VERSION> \
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
   docker run --rm openctemio/migrations:<VERSION> \
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
-- Release N+1 (000540_drop_owner.up.sql) — CONTRACT, destructive but now safe
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
   docker run --rm openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" version   # prints "<N> (dirty)"
   ```

2. **Fix the root cause.** Usually a **data violation** the migration's new
   constraint/FK/unique-index rejects. `scripts/preflight-migrate.sh --check-only`
   points at the exact offending rows for the known-risky migrations. Clean the
   data.

3. **Force the tracker to the last cleanly-applied version, then re-run:**

   ```bash
   # If version N failed and applied nothing, force to N-1 and re-migrate:
   docker run --rm openctemio/migrations:<VERSION> \
     -path=/migrations -database "$DATABASE_URL" force <N-1>

   docker run --rm openctemio/migrations:<VERSION> \
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

## Related

- [Kubernetes Deployment](kubernetes.md) — init-container / pre-deploy-Job manifests
- [Docker Deployment](docker.md) — the one-shot `migrate` compose service
- [Migrations (development)](../development/migrations.md) — authoring migrations
- `scripts/preflight-migrate.sh`, `scripts/migrate.sh`, `scripts/check-migrations.sh`
- `cmd/server/schema_check.go` — the fail-fast schema check + `SKIP_SCHEMA_CHECK`
