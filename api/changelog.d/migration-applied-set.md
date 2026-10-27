### Changed: migrations are tracked one by one, so a migration merged late is never skipped

- `openctem-migrate` (RFC-130) replaces golang-migrate in the migrations image, the all-in-one image, the binary and
  air-gap archives, the development entrypoint and CI. It records every applied migration in
  `schema_migrations_applied` and applies every shipped migration a database lacks, lowest version first: a migration
  merged after a higher-numbered one now runs instead of being skipped silently.
- New migrations take UTC timestamp versions (`make -C api migration-new`); versions only have to be unique. CI refuses
  a changed, removed or renamed merged migration and proves that a fresh install and an upgraded database get the
  same schema whatever order the migrations arrive in.
- The API refuses to start while any shipped migration is unapplied (not only when the newest one is), and the console
  and metrics read the highest applied version from the new table.
- **Upgrade note:** nothing to do. The first run takes the database over: it records the migrations golang-migrate had
  applied and puts a fence version in `schema_migrations`, after which an older migrations image refuses the database
  (as it already refused a database a newer release had migrated). Roll back the API image, not the migration job.
  The commands and arguments are unchanged; `force V` now records migration V as applied and `force -1` only clears
  the dirty flag (see "Dirty-migration recovery" in `docs/deployment/safe-deploy-and-migrations.md`).

### Security: only the migrator can write the migration tracking tables

- `deploy/postgres/least-privilege-roles.sql` creates `schema_migrations_applied` ahead of the first migration and
  gives the app role read-only access, like `schema_migrations`: a compromised API cannot make the next migration run
  skip or repeat a migration. Re-run the roles script on upgrade, as the compose stack and the deployment kit do.
