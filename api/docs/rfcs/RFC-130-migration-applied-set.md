# RFC-130: Migration applied set (versions only have to be unique)

| | |
|---|---|
| Status | Implemented |
| Scope | api (`cmd/openctem-migrate`, `internal/migrate`, `cmd/server` startup check, `internal/infra/postgres` ops snapshot, `deploy/postgres/least-privilege-roles.sql`, `scripts/migration-number.sh`, `scripts/migrate.sh`, `scripts/squash-migrations.sh`), CI (`check-migration-versions.sh`, `pr-migration-renumber.sh`, `migration-order-check.sh`, `schema-fingerprint.sql`, `upgrade-test.sh`), images (migrations, API, all-in-one, binary and air-gap archives) |
| Guide | [development/migrations.md](../development/migrations.md), [deployment/safe-deploy-and-migrations.md](../deployment/safe-deploy-and-migrations.md#the-migration-runner-openctem-migrate) |
| Architecture | [architecture/overview.md](../architecture/overview.md#database-migrations) |
| Related | RFC-053 (migration baseline) |

## 1. Summary

The earlier migration tool kept one number per database, the highest applied
version, and applied only files above it. A migration merged after a
higher-numbered one was skipped on every database already past it, without an
error. To keep that from happening, every migration had to be numbered above
the highest on `develop` at the moment it merged: with about fifteen open pull
requests carrying migrations and a merge queue that takes hours, numbers
collided all the time, queue entries failed on "not above the base", branches
were renumbered and pushed again (which also dropped their security acks), and
a reservation file was kept by hand.

`openctem-migrate` replaces the tool. It records every applied version and
applies every shipped migration a database has not applied, lowest version
first. A version only has to be unique, so new migrations take a UTC timestamp
version (`YYYYMMDDHHMMSS`) when they are written, and two pull requests never
need to agree on a number.

## 2. Design

### 2.1 State

Two tables in the connection's current schema:

| Table | Content |
|---|---|
| `schema_migrations_applied (version, name, applied_at)` | one row per applied migration: the truth |
| `schema_migrations (version, dirty)` | one row: `(9223372036854775807, false)` while clean (the *fence*), `(V, true)` while migration V failed midway |

The fence has no migration file, so an older migrations image (the earlier
tool) refuses the database ("no migration found for version ...") instead of
migrating it by its old rule, which would skip again. The dirty row keeps the
earlier tool, the startup check and the `SchemaDirty` alert refusing a
half-applied migration.

### 2.2 `up`

1. Take the migration lock: a session advisory lock with the earlier tool's
   key (so the two never run at once during an upgrade), polled with
   `pg_try_advisory_lock` from an idle session. A blocked `pg_advisory_lock`
   keeps a snapshot open, and `CREATE INDEX CONCURRENTLY` in the holder's
   migration would wait for it forever.
2. Create the two tables when missing (the roles script creates them ahead,
   owned by the migrator), in the schema current when the lock was taken;
   every statement of the run names that schema, so a migration that changes
   `search_path` cannot redirect the records. Then revoke INSERT, UPDATE,
   DELETE and TRUNCATE on both from every role but their owner (PUBLIC
   included): an install that never re-ran the roles script after the tables
   appeared would otherwise have given the app role full DML through the
   migrator's default privileges.
3. Refuse, changing nothing, on: a dirty database; a database a newer release
   migrated (an applied version above every shipped one); a database older
   than the migration baseline; a tracker another tool rewrote after the
   takeover; an undecidable takeover (2.3). An applied migration recorded
   under another name than the shipped file is reported as a warning.
4. For each pending migration, lowest version first: mark it dirty, run the
   file as one simple-protocol batch (one implicit transaction unless the file
   manages its own, exactly as before), then in one transaction record it and
   put the fence back.

`down N` rolls back the N most recently applied migrations (by when they were
applied, then by version). `force V` clears the dirty flag and records V
without running it; `force -1` only clears the flag, so `up` retries the failed
migration. On a database the earlier tool migrated, `force` first takes it
over as `up` would (2.3); on one that tool left dirty no release matches, so
`force` refuses without the operator's list (`-assume-applied`): clearing the
flag must neither forget nor invent which migrations below the failed one ran.
`status` lists what is pending.

### 2.3 Takeover of a database the earlier tool migrated

Such a database has only `schema_migrations`, at its highest version V. "Every
file up to V" is not what it applied: a release branch can carry a migration
numbered above one merged to develop later (v0.15.4 ships 003428; 003420
merged to develop afterwards), and the earlier tool skips the lower one
silently. So the runner ships `api/migrations/released.json`: for every
release tag that still shipped the earlier tool, exactly the migration
versions it contained (tags with the same set grouped), generated from the
tags by `scripts/released-migrations.sh` and checked in CI
(`released-migrations.sh --check`; the upgrade test also checks the previous
release is listed with its own files).

On the first run the runner records the files of the one release whose highest
version is V; every other shipped file, 003420 included, stays pending and
runs. It refuses, changing nothing, when no release ends at V (a database a
development build migrated: our own live environment), when releases with
different files end at V, or when the earlier tool left the database dirty.
The operator then lists the applied versions, checked against the schema, one
per line in a file, and passes it with `-assume-applied FILE` to `up` or
`force`; every listed version must be shipped (a typo is refused), and every
other file runs. At V equal to the migration baseline, the baseline alone is
recorded.

A release with the runner keeps the fence, never a bare version, so new tags
are not listed. A release tagged while it still ships the earlier tool (a
hotfix of an older line) makes the check fail until `make -C api
migrations-released` is committed.

Legacy numbers still added must be above the base's highest legacy number, and
none may be added once the base has a timestamp version (CI): six-digit
numbers are kept only for pull requests opened before this change.

### 2.4 Order independence

A migration merged after a higher version runs after it on running installs
and before it on a fresh install. CI proves both end with the same schema:
`migration-order-check.sh` migrates one database with the base commit's
migrations and then the tree's, another with the tree's only, and compares
their fingerprints (`schema-fingerprint.sql`: tables, columns, constraints,
indexes, views, functions, triggers, enums, domains, sequences, partitions,
policies; not data, owners, grants or physical column order). The upgrade test
compares the previous release upgraded to the tree with a fresh install the
same way.

### 2.5 CI gate

`check-migration-versions.sh`: versions are unique; an added migration has a
valid timestamp version (a legacy number is a warning, and an error at or below
the base's highest legacy number or once the base has a timestamp version); no merged up file is changed, removed or
renamed (a fix is a new migration; a baseline that replaces the chain is the
one exception); `released.json` matches the release tags. Pull request CI gives a clashing migration a new timestamp in
its runner only; `make -C api migration-renumber` does it for the branch.

## 3. Threat model

| Threat | Control |
|---|---|
| A compromised API process rewrites the tracking tables so the next run skips a security migration, or re-runs a destructive one | The app role has SELECT only on both tables (`least-privilege-roles.sql` creates them ahead, owned by the migrator, and revokes INSERT, UPDATE, DELETE; its verification and `least_privilege_test.go` fail otherwise) |
| The takeover marks a migration applied that never ran (one merged below a release's last migration after the release) | The takeover records only the files of the release that ends at the database's version (`released.json`, CI-checked against the tags); no match, an ambiguous match or a dirty database is refused until an operator lists the applied versions (DB tests) |
| An older migrations image migrates a taken-over database and skips silently | The fence: the earlier tool refuses a version that has no file |
| Two runners (replicas, a retried job, an old image) migrate at once | One advisory lock key shared with the earlier tool; concurrent-runner test |
| A half-applied migration is built on | Dirty state refuses every command but `force`; the server refuses to start |
| An install that never re-ran the roles script gives the app role write access to the tracking tables through default privileges | Every run revokes INSERT, UPDATE, DELETE and TRUNCATE on both tables from every role but the owner (DB test); it warns when its role cannot |
| A migration changes `search_path` and the run records into another schema's tables | Every statement names the schema captured with the lock (DB test) |
| The API starts on a newer release's database that lacks a migration this binary ships, or with a role that cannot read the tracker | The startup check computes the pending list even on a newer database and refuses on any pending migration and on a permission error |
| The database URL leaks the password | Deployments pass it in `PGPASSWORD`; the runner never prints the URL (tested) |
| A merged migration is edited after databases applied it | CI refuses a changed, removed or renamed merged up file |

No tenant data is read or written: the runner touches only its two tables and
whatever the migration files do. No new route, permission or tenant-scoped
query.

## 4. Upgrade

Nothing to do. The first `up` of a release with this runner takes the database
over (2.3) and puts the fence in place. After that an older migrations image
refuses the database, as it already refused a database a newer release had
migrated. The deployment kit, compose files, the binary install's
`openctem-migrate.service` and the all-in-one image call `openctem-migrate`
with the same arguments as before.

## 5. Implementation

- Runner: `api/internal/migrate`, command `api/cmd/openctem-migrate`.
- Unit and database tests: `internal/migrate/state_test.go`,
  `internal/migrate/runner_test.go` (missing in the middle, idempotence, dirty
  refusal and force, concurrent runners and the lock timeout, takeover from the
  earlier tool's state by release, a migration merged below the release's
  last one left pending, takeover without a matching release and with an
  operator's list, down order, refusals),
  `cmd/openctem-migrate/main_test.go`.
