# OpenCTEM REST API

The OpenCTEM API provides programmatic access to asset inventory, findings,
scans, scope and exposure management. All tenant routes are under `/api/v1/`;
sensors use `/api/v2/sensor/`.

```
https://openctem.example.com/api/v1/
```

- **Reference:** every running API serves its OpenAPI spec at `GET /openapi.yaml`
  and interactive documentation at `GET /docs`.
- **Authentication, errors, pagination, rate limits:** [endpoints.md](endpoints.md).
- **Style rules for new routes:** [API conventions](../architecture/api-conventions.md).
- Feature guides: [credential import](credential-import.md),
  [suppressions](suppressions.md).

## Endpoint groups

| Group | Prefix | Description |
|-------|--------|-------------|
| **Auth** | `/auth/` | Login, token exchange and refresh, OAuth, SSO, step-up |
| **Me** | `/me/`, `/users/me/` | The caller's account, sessions, 2FA, preferences, organizations |
| **Organization** | `/organization/`, `/tenants/` | Organization settings, members, invitations |
| **Assets** | `/assets/` | Asset inventory, services, relationships, state history, access grants |
| **Findings** | `/findings/`, `/vulnerabilities/` | Findings, activities, AI triage, suppressions; the CVE catalog |
| **Scans** | `/scans/`, `/scan-workflows/`, `/scan-runs/`, `/scan-zones/` | Scans, scan workflows, scan runs, zones |
| **Sensors** | `/sensors/`, `/sensor-pairings/` | Sensor management and pairing |
| **CI** | `/ci/` | CI trust configurations, pipelines, runs, gate |
| **Tools** | `/tools/`, `/tool-categories/` | Tool registry, scanner templates |
| **Scope** | `/scope/`, `/easm/` | Scope entries and exclusions, domain proof, EASM review |
| **Automations** | `/workflows/` | Automation definitions and triggers |
| **Exposures** | `/exposures/` | Exposures and threat intelligence |
| **Access control** | `/groups/`, `/roles/`, `/permissions/` | Roles and permissions; groups carry data scope |
| **Integrations** | `/integrations/` | Ticketing, notifications, SCM, SIEM |
| **Dashboard** | `/dashboard/` | Aggregated statistics |
| **Audit** | `/audit-logs/` | Audit log queries and chain verification |
| **MCP** | `/mcp` | Read-only MCP server ([mcp-server.md](../architecture/mcp-server.md)) |
| **Admin** | `/admin/` | Platform administration (console session only) |
| **Sensor protocol** | `/api/v2/sensor/` | Sensor commands, results, heartbeats (sensor key) |

The authoritative list is the spec; the groups above are a map.

## Health

`GET /health` (liveness) and `GET /ready` (database and Redis) need no
authentication.

## WebSocket

Real-time updates (finding activities, scan progress, notifications) are
delivered over a WebSocket at `/api/v1/ws`, authenticated with the session
cookie and an allowed `Origin`
([web security architecture](../../../web/docs/security-architecture.md#5-websocket--sse-security)).

## Generating the spec

```bash
make generate        # repository root: spec, route manifest, web types
make -C api swagger  # the spec only (api/api/openapi/swagger.yaml)
```
