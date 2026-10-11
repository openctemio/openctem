### Removed: unused duplicate and dead API routes (issue #970)

No caller in the web app, the e2e suites, sdk-go, the sensor, ctis, the MCP tools or the documentation. Every extra read path is one more place data scope must be re-applied, and duplicate writes carried their own permission gates.

- `GET /api/v1/services`, `/services/public`, `/services/stats`, `GET|PUT|DELETE /api/v1/services/{id}`: services are read and added through their asset (`GET|POST /api/v1/assets/{id}/services`).
- `GET /api/v1/state-history`, `/state-history/{id}`, `/state-history/stats`, `/state-history/timeline`, `/state-history/compliance`: use the "What changed" views (`/state-history/counts`, `/appearances`, `/disappearances`, `/newly-exposed`, `/exposure-changes`, `/shadow-it`) and `GET /api/v1/assets/{id}/state-history`.
- `GET /api/v1/relationships/usage-stats`.
- `GET /api/v1/finding-sources/categories`, `/categories/{id}`, `/code/{code}`, `/{id}`: `GET /api/v1/finding-sources?include_category=true` lists every source with its category.
- `PATCH /api/v1/findings/{id}/triage`: confirming a finding is `PATCH /api/v1/findings/{id}/status` with `confirmed`.
- `GET /api/v1/attachments/{id}/meta`: `GET /api/v1/attachments` lists the metadata.
- `GET|DELETE /api/v1/commands/{id}` and `POST /api/v1/commands/{id}/cancel`: a scan run is canceled as a whole (`POST /api/v1/scan-runs/{id}/cancel`); `GET /api/v1/commands` and `GET /api/v1/commands/{id}/logs` stay.
- `GET /api/v1/auth/oauth/providers`: use `GET /api/v1/auth/providers`.
- The permission `sensors:commands:delete` gated only the removed delete and is removed by migration 002015 (role grants, API key scopes and licenses drop it; no role loses access to anything).
- **Upgrade note:** API clients that called these routes get 404/405; move to the successors above.
