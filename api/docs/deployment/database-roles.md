# Least-privilege database roles

Decision D-6. The API used to connect to Postgres
as the superuser that owns the database. A SQL injection or an RCE in the API
was then full control of the cluster: read any file the server can read
(`pg_read_file`, `COPY ... FROM '/path'`), run programs (`COPY ... PROGRAM`),
drop the schema, create roles, and bypass row-level security and every grant.

This guide splits the database into three roles.

| Role | Used by | May |
|---|---|---|
| superuser (`DB_SUPERUSER`, e.g. `postgres`) | `initdb`, and the bootstrap script below | everything; the API never holds its password |
| `openctem_migrator` (`DB_MIGRATE_USER`) | the migrations (`migrate` job, all-in-one start-up) | own the application schemas: create, alter and drop tables, indexes (including `CREATE INDEX CONCURRENTLY`), functions, triggers, policies |
| `openctem_app` (`DB_USER`) | the API server and its workers | `SELECT`/`INSERT`/`UPDATE`/`DELETE` on the application tables; nothing else |
| `openctem_console` (`DB_ADMIN_USER`, optional) | the API's second, small pool for the platform console's identity tables | full DML on `admin_users`, `admin_credentials`, `admin_sessions`, `platform_identity_provider`, `admin_idp_login_states` and `admin_approvals` (alone), insert and read on `admin_audit_logs`, read on `admin_audit_chain_anchors` and `tenant_members`, read and update on `users`; nothing else |

Neither role is `SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION` or
`BYPASSRLS`. Neither belongs to `pg_read_server_files`, `pg_write_server_files`
or `pg_execute_server_program`, so neither can `COPY` to or from a server file
or a program. The app also cannot create objects in any schema, and it can only
read `schema_migrations`.

## What the API needs at run time

These were checked against the code and against the full test suite run as
`openctem_app` (see *How it is tested*).

| Need | Where | Grant |
|---|---|---|
| DML on every application table | everywhere | `SELECT, INSERT, UPDATE, DELETE` on all tables in `public` (the `deprecated` schema that 000213 created was dropped by 001059) |
| Sequences | `nextval` on serial columns | `USAGE, SELECT, UPDATE` on all sequences |
| Functions and trigger functions | triggers, `gen_random_uuid()` etc. | `EXECUTE` on all functions |
| `TRUNCATE epss_scores`, `TRUNCATE kev_catalog` | threat-intel feed refresh (`threatintel_repository.go`) | `TRUNCATE` on those two global tables only |
| A temporary table | EPSS bulk import stages rows with `CREATE TEMP TABLE` + `COPY ... FROM STDIN` | `TEMPORARY` on the database. `COPY FROM STDIN` needs only `INSERT` |
| Advisory locks | audit chain, sensor-result quarantine, EASM DNS, admin roster | none: any role may take advisory locks |
| `SET LOCAL app.current_tenant_id`, `set_config(...)` | RLS context middleware, tenant middleware | none: custom settings are allowed to any role |
| Reading `information_schema` | admin bootstrap, re-key job | none: a role sees the columns of the tables it has privileges on |
| `LISTEN`/`NOTIFY` | not used (job notifications use Redis pub/sub) | none |
| Extensions `pgcrypto`, `pg_trgm`, `uuid-ossp` | migrations | created by the bootstrap script as the superuser; the migrations' `CREATE EXTENSION IF NOT EXISTS` is then a no-op |
| Runtime DDL | none in the server. `CREATE INDEX CONCURRENTLY` and every `ALTER`/`CREATE` live in migrations | migrator only |
| Owner-rights functions | two `SECURITY DEFINER` functions, each doing one fixed job as the schema owner: `admin_audit_prune` (administrators' audit retention) and `dash_asset_day_maintain` (no input: creates the coming monthly partitions of `dash_asset_day` and drops those past the 13-month window; names come from dates only). Both pin `search_path`; `EXECUTE` is revoked from `PUBLIC`, and the console role does not get `dash_asset_day_maintain` | `EXECUTE` on those functions only; the app still cannot create or drop anything itself |

If a future change needs something the app does not have, the API fails with
`permission denied` (SQLSTATE 42501). Move the DDL into a migration; grant a
new privilege only in the bootstrap script, with the reason next to it.

## The bootstrap script

`deploy/postgres/least-privilege-roles.sql` creates or repairs both roles. Run
it as a superuser, connected to the OpenCTEM database:

```bash
psql "postgres://postgres@db-host:5432/openctem" -v ON_ERROR_STOP=1 \
  -v app_password="$DB_PASSWORD" \
  -v migrator_password="$DB_MIGRATE_PASSWORD" \
  -f deploy/postgres/least-privilege-roles.sql
```

`app_user` and `migrator_user` default to `openctem_app` and
`openctem_migrator`. A password variable left empty keeps the role's current
password. The script turns statement logging off for its own session, so the
passwords do not reach the server log.

It is idempotent. It:

1. creates the roles if missing and resets their attributes (no superuser, no
   `CREATEDB`/`CREATEROLE`/`REPLICATION`/`BYPASSRLS`), and revokes any role
   membership from the app;
2. creates the three extensions;
3. revokes `CONNECT`/`TEMPORARY` on the database and `CREATE` on the
   application schemas from `PUBLIC`, and makes the migrator the owner of the
   schemas;
4. moves every table, view, sequence, function and type in those schemas to
   the migrator (this is what an upgrade from the superuser layout needs);
5. grants the app the privileges in the table above;
6. sets `ALTER DEFAULT PRIVILEGES FOR ROLE openctem_migrator` so every table,
   sequence, function and type a later migration creates is granted to the app
   automatically;
7. verifies all of the above and fails (non-zero exit) if anything is off.

Run it again after restoring a dump, or after someone applied a migration as a
different role. That repairs ownership and grants.

### The console role

With `-v admin_user=openctem_console -v admin_password=…` the script also
creates the console role (same attributes as the app, no memberships) and
moves the platform console's identity tables to it:

- the app role loses `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` on `admin_users`,
  `admin_credentials`, `admin_sessions`, `platform_identity_provider`,
  `admin_idp_login_states` and `admin_approvals` (four-eyes approvals), and
  `SELECT` on all of them but `admin_users`
  (the trigger that keeps platform administrators out of organizations and the
  "is this account an administrator" checks read it);
- the console role gets no other table privilege than the ones listed in the
  table above. It cannot change or delete `admin_audit_logs` rows, and it
  cannot read or write tenant data.

The API then opens a second pool (`DB_ADMIN_USER`/`DB_ADMIN_PASSWORD`, at most
5 connections) for the administrator, console-session and platform identity
provider repositories. A SQL injection in any tenant-facing code path, which
runs on the app pool, can no longer add an administrator, read a console
session or credential, or swap the platform identity provider.

The console's organization, member and settings screens run on the app pool
(the same services as the tenant plane); only the repositories above use the
console pool. `bootstrap-admin` and `rekey` connect as the schema owner
(`DB_MIGRATE_USER`; in Compose run `docker compose run --rm bootstrap-admin ...`, a one-off
container that receives the owner credentials from `.env`, never `exec api`, whose
container must not hold them): they create or delete the sign-in account in `users` and
re-encrypt every location, which the console role cannot do. The script reruns after the migrations (`db-grants` in compose), so a
console table a release adds is moved before the API starts. If
`DB_ADMIN_USER` is set but the script did not run with `admin_user`, the API
logs an error at start-up saying the app role still writes `admin_users`.

## Configuration

Separate credentials, with the old single-role layout as the fallback:

| Variable | Meaning | Fallback |
|---|---|---|
| `DB_USER` / `DB_PASSWORD` | what the API connects as (`openctem_app`) | — |
| `DB_MIGRATE_USER` / `DB_MIGRATE_PASSWORD` | what migrations connect as (`openctem_migrator`) | `DB_USER` / `DB_PASSWORD` |
| `DATABASE_MIGRATE_URL` | all-in-one image only: the full migrator URL | built from `DB_MIGRATE_USER` |
| `DB_SUPERUSER` / `DB_SUPERUSER_PASSWORD` | compose: the bundled Postgres superuser and the `db-roles` job | `DB_USER` / `DB_PASSWORD` |
| `DB_ADMIN_USER` / `DB_ADMIN_PASSWORD` | the console role (API second pool); needs `DB_MIGRATE_USER`, which `bootstrap-admin` and `rekey` use | unset: the API writes the console tables as `DB_USER` |

### Limits of the app role

The bootstrap script sets two role-level limits on the app role (not on the
migrator, whose migrations may run long):

| psql variable | Default | Setting |
|---|---|---|
| `app_statement_timeout` | `60s` | `statement_timeout`: a query running longer is cancelled |
| `app_idle_in_transaction_timeout` | `60s` | `idle_in_transaction_session_timeout`: a session idle inside a transaction is closed |

A runaway query or a transaction left open by a crashed worker otherwise holds
locks and keeps vacuum from cleaning the tables it touched. `0` turns a limit
off. The values apply to new connections, so restart the API after changing
them.

**Tuning.** Look for `canceling statement due to statement timeout` (SQLSTATE
57014) in the API log after an upgrade. A statement that is cancelled and is
legitimate should raise its own limit in code (below); raise
`app_statement_timeout` only when many interactive statements on a very large
install need it, for example
`psql -f least-privilege-roles.sql -v app_statement_timeout=120s`, or in
compose set it where the `db-roles` job reads it and re-run `up`. Lower values
are fine on small installs. The idle-in-transaction limit should stay above the
longest pause between two statements of one transaction (an ingest batch
computing between statements stays well under 60s).

### Long statements

A statement that can legitimately outlast the role limit at scale raises its
own limit for its transaction with `SET LOCAL statement_timeout`, to one of two
bounded values (`internal/infra/postgres/statement_timeout.go`): 5 minutes for
one batched write and 15 minutes for one set-based statement over a table or
tenant. The helper refuses anything above 30 minutes, and the role limit
returns at commit. Every controller states how its SQL stays bounded in
`internal/infra/controller/statement_profile.go` (`light`, `batched` or
`long`); a test fails when a controller has no entry, so a new background job
must choose.

| Job | Statements | Limit |
|---|---|---|
| EPSS and KEV sync | full-feed upsert (temp table, chunked KEV upserts), prune, catalog propagation | 15 min / 5 min |
| Finding priority | EPSS/KEV intel enqueue, per-tenant reconcile enqueue, finding EPSS refresh batches | 15 min / 5 min |
| Dashboard facts | dirty-queue processing, full run steps, day-partition upkeep | 5 min / 15 min |
| CVE feed import | corpus chunk apply, bundle finish | 15 min |
| Software match | version vulnerability replace, invalidation after a feed delta | 5 min |
| Vulnerability events | corpus baseline, KEV and EPSS state sync, retention delete | 15 min / 5 min |
| Retention | audit chain prefix prune, finding evidence deletes, CI run token clearing, attachment orphan marking, web evidence deletes, sensor result purge, ingest report expiry | 5 min |
| Ingest | asset batch upserts, finding batch create and enrich, package writer, ingest payload clearing | 5 min |
| Asset merge | every re-key and delete of one merge | 15 min |
| Repository merge, program asset sync, attribution links, license verdicts | one transaction each | 5 / 15 min |
| Interactive reads | finding list 5s, endpoint list 3s, query engine 5s, finding export 60s | at or below the role limit, on purpose |

Work that is already in keyset or `LIMIT` batches (coverage planner, backfills,
the other sweeps and expiry jobs) stays under the role limit by construction
and sets nothing.

### Compression of large values

`deploy/docker-compose.yml` starts the bundled Postgres with
`default_toast_compression=lz4` (`PG_TOAST_COMPRESSION=pglz` restores the
built-in method), and migration `toast_lz4_large_columns` sets lz4 on the large
jsonb, text and bytea columns (finding description and scanner output, command
payloads, results and logs, ingest headers and payloads, sensor manifests,
finding evidence, AI triage raw responses). Only values written afterwards use
lz4; existing values stay readable and are not rewritten. On an external
Postgres built without lz4 the migration does nothing; set
`default_toast_compression = lz4` in its configuration where it is available.

- **`deploy/docker-compose.yml`** has a one-shot `db-roles` job. When `DB_MIGRATE_USER` is set, it
  runs the bootstrap script as `DB_SUPERUSER` on every `up`, before `migrate`,
  and `db-grants` runs it again after `migrate`, before the API.
  With `DB_ADMIN_USER` set both pass `admin_user`.
  `migrate` connects as `DB_MIGRATE_USER`, and the API as `DB_USER`. With
  `DB_MIGRATE_USER` unset, the job exits at once and nothing changes.
  `deploy/.env.example` sets up the split for new installations.
- **All-in-one image** (`deploy/allinone/supervise.sh`): migrations on start use
  `DATABASE_MIGRATE_URL`, or `DB_MIGRATE_USER`/`DB_MIGRATE_PASSWORD`, and fall
  back to the API's connection. Run the bootstrap script once against the
  external database first.
- **Helm** (the `helm-charts` repository): the migration job reads the
  migrator secret, and the API deployment reads the app secret.

## Moving an existing installation

The live order is:

1. Back up the database.
2. Generate two passwords. Run the bootstrap script as the current superuser
   (today that is usually `DB_USER`, e.g. `openctem`), with
   `-v app_password=… -v migrator_password=…`. It changes no data. It moves
   ownership and adds grants, so the running API (still the superuser) keeps
   working throughout.
3. Set the environment:
   - `DB_SUPERUSER=<old DB_USER>`, `DB_SUPERUSER_PASSWORD=<old DB_PASSWORD>`;
   - `DB_MIGRATE_USER=openctem_migrator`, `DB_MIGRATE_PASSWORD=…`;
   - `DB_USER=openctem_app`, `DB_PASSWORD=…`.
4. Restart in this order: `db-roles` (re-runs the script, a no-op) → `migrate`
   (as the migrator; a no-op if the schema is current) → the API. Then check
   `/health` and the API log for `permission denied`.
5. Optional, the console role: add `DB_ADMIN_USER=openctem_console` and a new
   `DB_ADMIN_PASSWORD` and run `up` again. `db-roles`/`db-grants` create the role
   and move the console tables; the API starts with the second pool. Console
   sessions survive (same table). To undo, unset both variables and run `up`:
   the script without `admin_user` grants the app its write on those tables
   again (as does an older release's script on a rollback), then the API
   starts with one pool. The console role can stay or be dropped.
6. **Rollback**: put `DB_USER`/`DB_PASSWORD` back to the superuser, unset
   `DB_MIGRATE_USER`, and restart the API. The superuser still owns everything
   implicitly, so nothing else needs reverting. The roles can stay.
   `DROP OWNED BY` / `DROP ROLE` would only be needed to remove them.

## How it is tested

- CI job **Tests (least-privilege DB role)** (`api-ci.yml`):
  1. bootstraps a fresh database with the script;
  2. applies every migration **as the migrator**, which proves no migration
     needs a superuser;
  3. re-runs the script, which proves it is idempotent;
  4. runs the DB-backed test suite with `DATABASE_URL` set to **`openctem_app`**.
     The handful of tests that replay migrations or alter constraints connect
     through `testdb.MigratorURL()` (`DATABASE_MIGRATE_URL`), exactly as
     production splits the two. Tests that create a scratch database
     (`testdb.PrivateDatabase`, the sensor-rename upgrade test, the bootstrap
     test) need CREATEDB, so they use `DATABASE_ADMIN_URL` (the superuser).
- `deploy/postgres/least_privilege_test.go` (runs when `DATABASE_ADMIN_URL` or `DATABASE_URL` is a superuser):
  - creates a scratch database and bootstraps it;
  - asserts the app role's attributes and memberships;
  - asserts that the app is refused `CREATE TABLE`, `COPY ... TO` a file,
    `pg_read_file`, `ALTER TABLE`, `DROP TABLE`, `TRUNCATE` on a tenant table and
    writes to `schema_migrations`;
  - asserts that a table created later by the migrator is usable by the app;
  - with `admin_user`: asserts the app reads `admin_users` and nothing more of
    the console's tables, and the console role writes them but cannot alter the
    admin audit log or the schema.

## Upgrading to v0.11.0

v0.11.0 adds the console table `admin_approvals` (the second-administrator
approvals). An installation that uses `DB_ADMIN_USER` re-runs the grant script
after upgrading so the console role can write it; the shipped Compose stack does
this itself through `db-grants`.
