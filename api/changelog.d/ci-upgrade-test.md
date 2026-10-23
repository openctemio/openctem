### Changed: CI upgrades the previous release's database to every release candidate

- A nightly workflow, and every release branch and release PR, builds the database of the last release tag (its own migrations, as the non-superuser migrator), loads representative rows, applies the new migrations and checks the version and dirty flag, the row counts of the key tables, and that the API starts against the result.
- No operator action. Keep rehearsing an upgrade on a copy of your own data (`docs/deployment/safe-deploy-and-migrations.md`).
