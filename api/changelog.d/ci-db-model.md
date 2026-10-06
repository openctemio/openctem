### Security: CI tables keep no email and reference their tenant's rows only

- `ci_gate_overrides.created_by_email` is dropped: the break-glass creator is its user id, and the email is read from the user when the override is shown. The gate verdict, which CI jobs print in their logs, no longer names the person who created the break-glass.
- `ci_runs` and `ci_pipelines` reference their trust configuration with the tenant (composite foreign keys): a row can never point at another organization's configuration. Deleting a configuration still keeps its runs and pipelines as history.

### Fixed: a repository's CI gate policy follows it on merge and goes with it on delete

- `ci_gate_policies.scope_id` is replaced by `repository_asset_id` and `business_unit_id`, each with a foreign key. Before, merging or deleting a repository left its gate policy pointing at nothing. The API is unchanged (`scope_type` + `scope_id`). Policies whose repository or business unit no longer exists are removed by the migration.

### Added: retention for CI runs

- An hourly job (one replica) deletes the per-run finding fingerprints of runs older than 90 days and runs older than 400 days, always keeping each pipeline's latest run and latest default-branch run, and clears run token hashes once the token has expired.
- Migrations `001113` (constraints, column split, email drop) and `001114` (validates the new trust-configuration keys without blocking writes).
- **Upgrade note:** on a large installation the first retention pass works in batches over several hours; nothing to do.
