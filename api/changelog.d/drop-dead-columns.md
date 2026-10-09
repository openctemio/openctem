### Removed: retired and never-read columns (migration 001483)

- Migration 001483 drops `users.federated_issuer` and `users.federated_subject` (moved to `user_identities` by 001306, empty since), `tenants.members_without_group_see` and its CHECK (retired by decision D2; pinned to `nothing` by 000910), `admin_credentials.password_hash` and `password_changed_at` (the console signs in with the linked account plus TOTP; the stale console password hash is deleted with the column), `event_types.default_severity` and `licenses.is_osi_approved`, `is_fsf_libre`, `is_deprecated`, `limitations` (never read).
- `sensors.type` no longer accepts `agent` (the pre-rename name) or `platform`; the API already refused both and no row holds them.
- The migration stops with an error, instead of silently dropping it, if any other constraint or index uses one of these columns.
- **Upgrade note:** one step, no code change needed. Run the migration explicitly; `air` does not run migrations.
