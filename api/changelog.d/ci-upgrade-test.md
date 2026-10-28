### Changed: CI upgrades the previous release's database to every release candidate

- A nightly workflow, and every release branch and release PR, builds the database of the last release tag (its own migrations, as the non-superuser migrator), loads representative rows, applies the new migrations and checks the version and dirty flag, the row counts of the key tables, and that the API starts against the result. When the last release still shipped golang-migrate, it first checks that `api/migrations/released.json` lists that release with exactly the migrations it shipped (the takeover data `openctem-migrate` needs).
- No operator action. Keep rehearsing an upgrade on a copy of your own data (`docs/deployment/safe-deploy-and-migrations.md`).
