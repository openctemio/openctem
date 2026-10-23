### Removed: PUT on the finding approval settings

- `PUT /api/v1/organization/settings/finding-approvals` is removed: the settings are a partial update and use `PATCH` (same body, same gate: owner or administrator, `settings:write`, recent re-authentication). The web console's Settings > Finding approvals page now saves with `PATCH`.
- **Upgrade note:** an API client that changed these settings with `PUT` sends the same body with `PATCH`.
