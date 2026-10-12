### Removed: the separate tenant-tools, custom-tools and custom-tool-categories APIs

- Tools are one resource, `/api/v1/tools`: the organization's view of the catalog (platform tools plus its own custom tools). `include=settings,availability,stats` adds its settings, the availability from its sensors and run statistics in the same call.
- **Upgrade note (old → new):**

| Old | New |
|---|---|
| `GET /tools/platform` | `GET /tools?source=platform` |
| `GET /tools/name/{name}` | `GET /tools?q={name}` |
| `POST /tools/{id}/activate`, `/deactivate` | removed (platform tools are managed by the platform); `PATCH /tools/{id}/settings {"is_enabled":…}` switches a tool for the organization |
| `GET /custom-tools` | `GET /tools?source=custom` |
| `GET /custom-tools/{id}` | `GET /tools/{id}` |
| `POST /custom-tools` | `POST /tools` |
| `PUT`/`DELETE /custom-tools/{id}` | `PUT`/`DELETE /tools/{id}` |
| `POST /custom-tools/{id}/activate`, `/deactivate` | `PATCH /tools/{id}/settings {"is_enabled":…}` |
| `GET /tenant-tools`, `GET /tenant-tools/{toolId}` | `GET /tools?include=settings`, `GET /tools/{id}?include=settings` |
| `PUT /tenant-tools/{toolId}` | `PATCH /tools/{id}/settings` (an omitted field is left as it is) |
| `DELETE /tenant-tools/{toolId}` | `PATCH /tools/{id}/settings {"config":{},"is_enabled":true}` |
| `GET /tenant-tools/{toolId}/effective-config` | `GET /tools/{id}?include=settings` (`settings.effective_config`) |
| `GET /tenant-tools/{toolId}/with-config` | `GET /tools/{id}?include=settings,availability` |
| `GET /tenant-tools/all-tools` | `GET /tools?include=settings,availability` |
| `GET /tenant-tools/availability` | `GET /tools?include=availability` (summary and unlisted tools in `availability`) |
| `POST /tenant-tools/bulk/enable`, `/disable` | `PATCH /tools/settings {"tool_ids":[…],"is_enabled":true\|false}` |
| `GET /tenant-tools/stats`, `/stats/{toolId}` | `GET /tools?include=stats`, `GET /tools/{id}?include=stats` |
| `GET /tool-categories/all` | `GET /tool-categories?per_page=100` |
| `POST /custom-tool-categories`, `PUT`/`DELETE /custom-tool-categories/{id}` | `POST /tool-categories`, `PUT`/`DELETE /tool-categories/{id}` |

### Security: tool authorization per action on the one resource

- Reading the catalog needs `scans:tools:read`. Each include needs the permission of its former standalone route: `scans:tenant_tools:read`, and `scans:read` as well for `stats` (tenant-wide counts over every scan). One the caller may not read is left out and named in `meta.omitted_includes` (200, never a 403). Sensor names and zones in the availability still need `sensors:read`.
- `include` (one shared implementation, `internal/infra/http/include`) takes at most 3 known values; an unknown, nested or extra value is refused with `INVALID_INCLUDE`. `per_page` is capped at 100, and at 50 with availability or stats, which also cost 2 more read-limit tokens each. A response that took `include=` is `Cache-Control: private, no-store`.
- Tool settings never hold secrets: a config with a secret-shaped key or value is refused (400); credentials belong in the secret store, referenced by id. A config stored before this rule is masked on read.
- **Behaviour change:** config overrides (`PATCH /tools/{id}/settings` with `config`) need `scans:tools:write` (admins and owners by default), since they change what the sensors run. Members keep the on/off switch.
- **Behaviour change:** creating, changing and deleting custom tools and custom categories needs `scans:tools:write` / `scans:tools:delete` (admins and owners by default). Members, who held `scans:tenant_tools:write`, no longer create custom tools (whose install commands sensors run); they still switch tools on or off (`PATCH /tools/{id}/settings` with `is_enabled`, `PATCH /tools/settings`).
- A platform tool or category, or another organization's, answers 404 on `PUT`, `DELETE` and `PATCH …/settings`; the service resolves the tool by tenant and id. Changing a platform category used to answer 403 and reading a platform category that is not builtin answered 404.
