### Security: service accounts get their own permission, keep the full-data ceiling through teams, and their keys no longer outlive the administrator who minted them

- New permission `service_accounts:manage` (migration `service_accounts_manage_permission`): creating and deleting a service account and minting or deleting its API keys no longer need only `team:members:write`. Owners and administrators hold it; a custom role can carry it.
- **Upgrade note:** a custom role that created service accounts with `team:members:write` must be given `service_accounts:manage`.
- A service account cannot get full data access through a team either way round: the service already refused it, and triggers on `group_role_bindings` and `group_members` (migration `service_account_team_ceiling`) now refuse it for any other writer.
- When a member is offboarded or leaves, or an administrator or owner is demoted to member or viewer, the active service-account keys they minted are revoked and audited. The member access report lists them first (`service_account_keys`) and the offboarding result and the audit events carry `revoked_service_account_keys`; the console shows both.
- API keys are read-only, so minting a key with a write scope (anything but `*:read` or `*:view`) is refused with 400 and the key dialog offers read scopes only.
