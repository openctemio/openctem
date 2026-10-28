---
name: migration
description: Rules for writing a database migration in api/migrations - timestamp versions, never editing a merged migration, reversible down, safety on populated tables, tests that find a migration by name, destructive-change notes. Use whenever a change adds or edits a migration or a seed row.
---

Full reference: `api/docs/development/migrations.md`; design: `api/docs/rfcs/RFC-130-migration-applied-set.md`.

1. **Version:** `YYYYMMDDHHMMSS_<snake_name>.{up,down}.sql`, created with `make -C api migration-new name=<snake_name>`
   (the current UTC time; no network, no coordination). `openctem-migrate` applies every migration a database has
   not applied, so a version only has to be **unique**: a migration merged after a higher one still runs. Never
   pick or change a version by hand. If CI reports a duplicate, or your branch still has a legacy six-digit
   number, run `make -C api migration-renumber` and commit the staged renames. Do not renumber on every rebase:
   below `develop`'s highest is fine for a timestamp.
2. **A merged migration never changes.** Databases that applied it never run it again, so an edit, a removal or a
   rename reaches only fresh installs. Fix it with a new migration. CI ("Migration Versions") refuses a changed,
   removed or renamed merged up file.
3. **Order independence:** your migration may run before (fresh install) or after (running install) migrations
   merged while your PR waited. CI ("Migrations (PostgreSQL 18)", `migration-order-check.sh`) compares both
   schemas. If yours depends on a migration that is not merged yet, it must have a higher version and merge after it.
4. **Tests find the migration by name:** `testdb.MigrationVersion(t, dir, "<snake_name>")`, never a hard-coded
   version, so a new version only renames files.
5. **Reversible:** every `up` has a working `down`. Test up, down, up on a scratch Postgres
   (`openctem-migrate ... up`, `down 1`, `up`).
6. **Safe on real data:** the database has populated tables.
   - backfill before adding `NOT NULL`, or add it with a default;
   - avoid long locks (create indexes concurrently where the tooling allows, batch large updates);
   - when replacing a table or column, copy the rows into the replacement first and check the counts;
   - never drop data that has no replacement without the owner's yes; keep audit history.
7. **Destructive changes** (drop, rename, type change) mean the API must stop during deploy, because old code
   cannot read the new shape. Say so in the PR body and in the changelog fragment as an upgrade note. Legacy
   removal does not have to wait for a release: one-step upgrade notes are fine.
8. **Tenant tables:** a new table holding tenant data has `tenant_id` (not null, indexed, in every unique key
   that should be per tenant) and its queries always filter on it.
9. **Seeds:** permissions and roles change through migrations, additive, with a down. Seed files never carry test
   users, test tenants or real emails (use `example.com` or `*.test`).
10. **Functions and comments:** follow the PostgreSQL function convention in the reference doc. A short file
    header may name the RFC; do not repeat RFC or phase tags in every comment.
11. **Schema drift:** CI compares the migrated schema; regenerate anything it derives from the schema.
12. **Never touch the tracking tables** (`schema_migrations`, `schema_migrations_applied`) from a migration or the
    API; only `openctem-migrate` writes them (`force` after a failed migration, see the reference doc).
