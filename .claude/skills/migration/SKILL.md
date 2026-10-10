---
name: migration
description: Rules for writing a database migration in api/migrations - numbering, reversible down, safety on populated tables, tests that find a migration by name, destructive-change notes. Use whenever a change adds or edits a migration or a seed row.
---

Full reference: `api/docs/development/migrations.md`.

1. **Number:** `NNNNNN_<snake_name>.{up,down}.sql`, above the highest on `develop` and in open PRs (use the
   band you were given, if any). Numbers have gaps; never count files. The "Migration Versions" CI step fails a
   duplicate or a version not above the base's highest (in the merge queue, the base includes queued groups).
   If `develop` overtakes you, the merge tooling renames the files at merge time; do not hand-renumber in
   every rebase.
2. **Tests find the migration by name:** `testdb.MigrationVersion(t, dir, "<snake_name>")`, never a hard-coded
   version, so a renumber only renames files.
3. **Reversible:** every `up` has a working `down`. Test up, down, up on a scratch Postgres.
4. **Safe on real data:** the database has populated tables.
   - backfill before adding `NOT NULL`, or add it with a default;
   - avoid long locks (create indexes concurrently where the tooling allows, batch large updates);
   - when replacing a table or column, copy the rows into the replacement first and check the counts;
   - never drop data that has no replacement without the owner's yes; keep audit history.
5. **Destructive changes** (drop, rename, type change) mean the API must stop during deploy, because old code
   cannot read the new shape. Say so in the PR body and in the changelog fragment as an upgrade note. Legacy
   removal does not have to wait for a release: one-step upgrade notes are fine.
6. **Tenant tables:** a new table holding tenant data has `tenant_id` (not null, indexed, in every unique key
   that should be per tenant) and its queries always filter on it.
7. **Seeds:** permissions and roles change through numbered seed migrations, additive, with a down. Seed
   files never carry test users, test tenants or real emails (use `example.com` or `*.test`).
8. **Functions and comments:** follow the PostgreSQL function convention in the reference doc. A short file
   header may name the RFC; do not repeat RFC or phase tags in every comment.
9. **Schema drift:** CI compares the migrated schema; regenerate anything it derives from the schema.
