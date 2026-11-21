### Added: API keys show an expired state, owner and owner filter; service accounts list roles, teams and the AI agent mark

- `GET /api/v1/api-keys`: an active key past its expiry reads `expired` (derived at read time, rows are not rewritten, the `status` filter follows it); each key carries `owner_name` and `owner_kind`; `?owner=me|service_accounts` narrows the list. The `api_keys` count of a service account no longer includes expired keys.
- `GET /api/v1/service-accounts`: each account carries `roles`, `teams` and `ai_agent`. Tenant-scoped, two grouped queries for the whole list. No migration, no permission change.
- Docs: server/docs/architecture/api-keys.md, server/docs/architecture/console-api-screens.md
