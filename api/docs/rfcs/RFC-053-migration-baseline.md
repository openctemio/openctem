# RFC-053: Migration baseline (squash the migration chain)

| | |
|---|---|
| Status | Implemented (draft PR, merges in a quiet merge-queue window) |
| Scope | api (`migrations/`, `scripts/`, `cmd/server`, `cmd/gen-asset-types`, tests), CI (`.github/scripts/check-migration-versions.sh`), images (migrations, all-in-one) |
| Guide | [development/migrations.md](../development/migrations.md#migration-baseline), [deployment/safe-deploy-and-migrations.md](../deployment/safe-deploy-and-migrations.md#migration-baseline-upgrading-an-older-database) |

## 1. Summary

`api/migrations` held 790 files (395 migrations, numbered up to 001146). Every
fresh install, every CI job and every private test database applied all of
them, and the tree carried tests and runbooks for data migrations that every
existing database ran long ago.

They are replaced by one **baseline**, `001146_baseline.up.sql`: a `pg_dump`
of the database the chain produces (schema and built-in rows, no owners, no
grants), generated and verified by `scripts/squash-migrations.sh`. New
migrations continue above it. A database already at 001146 or later is
untouched; one older than 001146 is refused with instructions and is upgraded
through the last release before the baseline first.

The squash also drops the two tables that only fed down migrations of the
replaced chain, `priority_rule_safety_report` (000942) and
`role_permissions_admin_only_stripped` (000945): the baseline leaves them out
and migration `001147` drops them on existing databases. Nothing else is
dropped; every other table, empty or not, belongs to a planned feature.

## 2. How golang-migrate treats a baseline

golang-migrate (v4.18, the version CI and the images use) keeps one row in
`schema_migrations (version bigint, dirty boolean)`.

- `up` reads the current version V0 and applies, in order, every file whose
  version is above V0. Before that it checks that **a file for V0 exists**
  (`versionExists`); if not, it stops with `no migration found for version V0:
  read down for version V0 .: file does not exist` and changes nothing.
- A file is run as one multi-statement `Exec`, which PostgreSQL executes as one
  implicit transaction. Before running it, golang-migrate sets the version to
  the file's and `dirty = true`; after success it clears `dirty`. A failure
  rolls the file back and leaves the version dirty.
- `down N` runs down files from the current version downwards.

What that means for a baseline at version B (= the highest version of the
chain it replaces):

| Database | What happens |
|---|---|
| empty (no `schema_migrations`, or no row) | applies `B_baseline`, then everything above B |
| at version B | `B_baseline.up.sql` exists, so the check passes; only versions above B run |
| at a version above B | same; the baseline is never run |
| at a version below B | refused before any change: its version has no file |
| `migrate down` to below B | the baseline's down file raises an exception: nothing is dropped. golang-migrate has already marked the tracker dirty (version -1); `migrate force B` puts it back |

No `migrate force` is needed anywhere, and no existing database ever runs the
baseline. The baseline also refuses to run when the database already has the
schema (`to_regclass('public.tenants')`), which covers a tracker that was
deleted or forced by hand.

## 3. The baseline file

`scripts/squash-migrations.sh REF` (default `origin/develop`):

1. extracts `api/migrations` at REF with `git archive` (the work tree does not
   matter), B = its highest version;
2. applies the chain with golang-migrate to a throwaway `postgres:17-alpine`;
3. `pg_dump --no-owner --no-privileges --column-inserts`, without
   `schema_migrations` and the tables in `EXCLUDE_TABLES`;
4. writes `B_baseline.up.sql`: a header (generated from commit X, do not
   edit), `SET check_function_bodies = false` (SQL functions may name tables
   created later in the file), the guard, the dump body, `RESET`. Only the
   dump's own header (psql session settings that would otherwise stay on
   golang-migrate's pooled connection), `SET default_table_access_method` and
   the `COMMENT ON EXTENSION` statements (they need the extension's owner and
   repeat what `CREATE EXTENSION` sets) are removed. Everything else is copied
   byte for byte; no line is rewritten, because a function body can contain
   any line;
5. writes `B_baseline.down.sql`, which raises an exception;
6. removes every work-tree migration up to B (`git rm`).

Properties:

- **No owners, no grants.** Objects belong to whichever role runs the file
  (the migrator in production, D-6) and the app role gets DML from
  `deploy/postgres/least-privilege-roles.sql` and the migrator's default
  privileges, exactly as with the chain (no migration ever granted anything).
- **Built-in rows are data, not code.** Permissions (161), system roles and
  their permissions, modules, tools, capabilities, compliance frameworks,
  asset types, the system tenant and the other catalogue rows are `INSERT`s
  with the values the chain produced. Values the chain computed at run time
  (`now()`, `gen_random_uuid()`, `uuidv7()`) are fixed at generation time.
- **RLS stays in shadow mode**: the 92 policies are created, no table has row
  level security enabled.
- **Extensions**: `CREATE EXTENSION IF NOT EXISTS` for `pg_trgm`, `pgcrypto`,
  `uuid-ossp`; the least-privilege bootstrap creates them first, as before.
- 26,210 lines, 1.4 MB. Applying it takes about a second.

## 4. Proof that the baseline is the chain

`squash-migrations.sh` verifies after generating (and alone with
`VERIFY_ONLY=1`). On fresh databases it builds

- **A** = REF's chain + the work tree's migrations above B, and
- **B** = the work tree (baseline + the migrations above B),

twice each: as the superuser, and as the least-privilege migrator the way
the CI job does it (bootstrap, migrate as `openctem_migrator`, bootstrap
again). It then compares:

- `pg_dump --schema-only` (with owners and grants in the least-privilege run):
  byte-identical, except for one way PostgreSQL prints an expression after a
  dump and restore. `col IN ('a','b')` on a varchar column is stored as
  `text = ANY` of a varchar array cast to `text[]`; printed and read back, the
  cast moves onto each element. Both forms mean the same check; the first is
  rewritten to the second before comparing (233 lines on the chain side, 0 on
  the baseline side), nothing else is;
- `pg_dump --data-only --column-inserts`: identical after masking `now()`
  timestamps and v4/v7 UUIDs, and dropping pg_dump's `-- Data for Name`
  comments (it orders those of empty tables arbitrarily). Two independent
  chain runs are compared the same way, which shows the masking hides only
  run-time values;
- `schema_migrations`: both at 1147, not dirty.

Result at develop `d968c4404` (B = 001146):

```
super — chain vs baseline
  identical: super-schema (23714 lines)
  identical: super-data (1743 lines)
super — chain vs chain
  identical: super-data-chain (1743 lines)
lp — chain vs baseline
  identical: lp-schema (26327 lines)   # owners, 368 GRANTs, 4 default ACLs
  identical: lp-data (1743 lines)
lp — chain vs chain
  identical: lp-data-chain (1743 lines)
```

Both sides: 229 tables, 56 functions, 84 triggers, 92 policies (0 tables
with RLS enabled), 424 comments, 368 grants to the app role.

## 5. Rehearsal on the live backup

A restore of `openctem-pre-deploy-20261005T155102Z.dump` (version 1046) into a
scratch PostgreSQL 17:

1. the new tree through the migrations image's entrypoint: refused, version
   still 1046, with the instructions of §6;
2. the pre-squash chain (`origin/develop`) up to 1146: clean;
3. the new tree: applies only `001147`; the schema diff before/after is
   exactly the two ledger tables (both had 0 rows);
4. the upgraded schema compared with a fresh install (baseline + 001147),
   owners ignored, the IN-list form normalised: **no difference**;
5. the full API test suite against the upgraded copy: see the PR.

## 6. A database older than the baseline

golang-migrate refuses it without changing anything (§2). The refusal is
spelled out in three places:

- the migrations image's entrypoint, `scripts/migrate-entrypoint.sh`
  (installed as `/usr/local/bin/openctem-migrate`, arguments unchanged, so
  compose and the Helm chart need no change), also used by the all-in-one
  image's `supervise.sh`: when migrate fails with "no migration found for
  version N" and N is below the baseline, it prints what to do;
- the API's startup check (`cmd/server/schema_check.go`): a database whose
  version is below the baseline is refused with the same instructions, before
  the "schema is behind" check;
- the baseline's guard, for a database that has the schema but no version.

The way out: back up, deploy the last release before the baseline (git tag
`pre-baseline-001146`, which ships every old migration), run its migrations,
then deploy the new release. The old files stay reachable at that tag
(`git show pre-baseline-001146:api/migrations/<file>`).

## 7. What reads the migrations, and what changed

| Reader | Change |
|---|---|
| CI `Tests (Postgres + Redis)`, `Tests (least-privilege DB role)` (`migrate up`, then the suite; LP: bootstrap → migrate as migrator → bootstrap) | none; they apply 2 files instead of 387 |
| CI `Migration Safety` (`scripts/check-migrations.sh`) | none; the baseline and `001147` carry `expand-contract-ok` with a reason |
| CI `Migration Versions` (`.github/scripts/check-migration-versions.sh`) | an added `NNNNNN_baseline` may be at or below the base's highest version if it is the lowest version left in the tree; added files are now found with `--no-renames` (a file that replaces a base migration was a "rename" and went unchecked). Tests 8 and 9 |
| CI `SQL Schema Drift` (`scripts/check-sql-schema.sh`) | none; 1409/1419 statements verified, as before |
| CI `Asset Types Drift` (`cmd/gen-asset-types -check`) | the dump keeps no registry markers: when no migration above the baseline carries the block, the migration half is left to the database tests (`TestAssetTypeRegistry_*`), which compare the migrated schema with the YAML; the next registry migration brings the static check back |
| `scripts/preflight-migrate.sh`, `make migrate-preflight` | removed: its only checks were for 000170/000171, which no database can still be before |
| `cmd/server/schema_check.go` | refuses a database older than the baseline (§6) |
| `api/Dockerfile.migrations` | entrypoint `openctem-migrate` (§6) |
| all-in-one (`deploy/allinone`) | runs `openctem-migrate`, copied from the API image |
| seed image (`Dockerfile.seed`, `migrations/seed`) | none |
| `web/e2e/ci/compose.yml` (`migrate/migrate` image on the directory) | none |
| `internal/testdb.PrivateDatabase` (each test's own database, migrated through `DATABASE_ADMIN_URL`) | none; `PrivateDatabaseThrough` removed (its only user replayed a squashed migration) |
| `tests/unit/permission_catalog_sync_test.go` | reads the permission rows of the baseline, then the seed/rename/remove migrations listed above it (none yet) |
| `tools/lint/tenantsql/tenant_tables.txt` | the two ledger tables removed |
| Helm chart (separate repository) | none needed: the Job passes migrate's arguments to the image entrypoint. A `migrations.downMigration.steps` that reaches the baseline is refused by its down file |

Removed tests (each replayed one squashed migration's up/down on seeded data;
the behaviour they left behind is in the schema and is covered by the
remaining tests): 000245, 000267, 000230 (sensor rename upgrade), 000292,
000294, 000300, 000301, 000340, 000372, 000640, 000751, 000778, 000910,
000921/000922 replay, 000942, 000945, 001012, 001018, 001061 up/down, and the
RFC-044 definition-catalog replay.

## 8. Numbering and open PRs

- New migrations continue above the highest number on `develop` (`001147`
  after this change). `agent-ops/queueall.sh` takes the maximum over develop
  and every open PR and renumbers a PR whose migration is at or below it; that
  keeps working unchanged (develop's maximum is 001147 after the squash).
- An open PR that **adds** a migration above the baseline: nothing to do.
- An open PR that **edits or reads** a squashed migration file, or a test that
  replays one (`os.ReadFile("../../migrations/0009xx_...")`,
  `testdb.PrivateDatabaseThrough`): fails after merging develop. Express the
  change as a new migration, and drop the replay test.
- An open PR that adds a permission: add its migration to
  `permSeedMigrations` in `permission_catalog_sync_test.go`, as before.

## 9. Security

- **Integrity of the baseline.** It is generated, not written: anyone can
  regenerate it from the named commit and compare (`VERIFY_ONLY=1` reruns the
  proof). Review checks the script, not 26,210 lines.
- **Privileges.** The baseline grants nothing and needs no superuser: the
  least-privilege CI job applies it as `openctem_migrator`. The grant set of
  the app role is byte-identical to the chain's (§4), so the D-6 boundary
  (DML only, no DDL, no TRUNCATE except the two feed tables) is unchanged.
- **Tenant isolation.** The schema is identical, including every composite
  tenant foreign key, check constraint, trigger and the shadow-mode policies;
  no query changes.
- **No data leaves.** The baseline holds only rows a fresh install creates
  (catalogues, the system tenant); no secret, no customer row. The rehearsal
  restored live data only into a local scratch container, removed afterwards.
- **Safe failure.** An older database is refused before any change; the
  baseline refuses a database that already has the schema; its down migration
  refuses instead of dropping every table.

## 10. Alternatives considered

- **Keep the chain.** Every install and test database keeps replaying 387
  migrations, and the tree keeps tests and runbooks for data fixes that ran
  everywhere long ago.
- **Squash at the last release tag.** The newest release (v0.8.0) stops at
  000224; squashing there leaves most of the chain.
- **A hand-written baseline.** Cannot be shown equal to the chain; a dump can.
- **`migrate force B` on existing databases.** Unnecessary: a database at B
  already passes golang-migrate's check, and forcing an older one would skip
  real migrations.
