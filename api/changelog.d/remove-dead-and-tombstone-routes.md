### Removed: refusal stubs and routes nothing calls

- The shared-catalog refusal stubs are gone: `POST /api/v1/vulnerabilities`,
  `PUT`/`DELETE /api/v1/vulnerabilities/{id}`, `POST /api/v1/threat-intel/sync`
  and `PATCH /api/v1/threat-intel/sync/{source}` always answered 403. They now
  answer 405. The platform operator still syncs and toggles the feeds from
  `/api/v1/admin/threat-intel`.
- Routes with no caller in the web console, the SDK, the sensor, the scripts
  or the public docs are removed, with their handlers and service code:
  `POST`/`DELETE /api/v1/findings/{id}/link-ticket` (use `create-ticket`),
  `GET /api/v1/findings/analytics/sources`,
  `PATCH /api/v1/tenants/{tenant}/settings/branch`,
  `POST /api/v1/assets/import/kubernetes` (the CSV import stays),
  `POST /api/v1/integrations/{id}/import-repositories` (the integration sync
  still imports repositories), and the deprecated
  `GET /api/v1/asset-types/categories[/{categoryId}]` (use `GET /api/v1/asset-types`).
- `POST /api/v1/findings/ai-triage/bulk` is deprecated: it sends `Deprecation`
  and `Sunset` (2027-01-15) headers. Triage one finding with
  `POST /api/v1/findings/{id}/ai-triage`.
- **Upgrade note:** a client that called a removed route gets 404 or 405.

### Removed: the findings:vulnerabilities:write and :delete permissions (migration 001178)

- With the refusal stubs gone nothing checks them (the shared CVE catalog has
  no tenant writes), so they are removed from the catalog and from the owner
  and admin roles. No role loses access to anything. The rows are archived
  and the down migration restores them.
