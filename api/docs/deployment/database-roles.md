# Least-privilege database roles

Owner decision D-6 (research/14, SEC-7). The API used to connect to Postgres
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

## Configuration

Separate credentials, with the old single-role layout as the fallback:

| Variable | Meaning | Fallback |
|---|---|---|
| `DB_USER` / `DB_PASSWORD` | what the API connects as (`openctem_app`) | — |
| `DB_MIGRATE_USER` / `DB_MIGRATE_PASSWORD` | what migrations connect as (`openctem_migrator`) | `DB_USER` / `DB_PASSWORD` |
| `DATABASE_MIGRATE_URL` | all-in-one image only: the full migrator URL | built from `DB_MIGRATE_USER` |
| `DB_SUPERUSER` / `DB_SUPERUSER_PASSWORD` | compose: the bundled Postgres superuser and the `db-roles` job | `DB_USER` / `DB_PASSWORD` |

- **`deploy/docker-compose.yml`** (full stack) and **`docker-compose.prod.yml`**
  (API only) have a one-shot `db-roles` job. When `DB_MIGRATE_USER` is set, it
  runs the bootstrap script as `DB_SUPERUSER` on every `up`, before `migrate`.
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
5. **Rollback**: put `DB_USER`/`DB_PASSWORD` back to the superuser, unset
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
  - asserts that a table created later by the migrator is usable by the app.
