### Behaviour change: migrations start from one baseline (RFC-053)

- The 395 migrations up to 001146 are replaced by `migrations/001146_baseline.up.sql`, the schema and built-in rows they produced, generated and verified by `scripts/squash-migrations.sh`. A fresh install applies one file; the resulting database is the same (schema byte-identical, grants of the least-privilege app role identical).
- A database at migration 001146 or later upgrades as usual. A database older than 001146 is refused before anything changes, by the migrations image, the all-in-one image and the API's startup check, with instructions.
- **Upgrade note:** before deploying this release, run the migrations of the last release before the baseline (git tag `pre-baseline-001146`), so the database is at 001146. Back up first.

### Removed: down-migration ledger tables

- Migration 001147 drops `priority_rule_safety_report` and `role_permissions_admin_only_stripped`. They recorded what migrations 000942 and 000945 changed, for their down migrations, which the baseline replaced; no code read them.
- `scripts/preflight-migrate.sh` and `make migrate-preflight` are removed: their only checks were for migrations 000170 and 000171.
