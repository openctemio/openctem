# MCP server (read-only AI access to CTEM data)

> Shipped vs planned. See [RFC-016](../rfcs/RFC-016-mcp-server.md) for rationale.

OpenCTEM exposes a read-only **Model Context Protocol** server so an AI client
(Claude Desktop/Code, or any MCP host) can query a tenant's CTEM data in natural
language. It reuses existing tenant-scoped read services — no new data path, no
schema change.

## Endpoint

```
POST /api/v1/mcp
Authorization: Bearer oct_<tenant-scoped-api-key>
Content-Type: application/json
```

JSON-RPC 2.0. A single request/response per POST (`application/json`); no SSE.
Supported methods: `initialize`, `notifications/*` (acknowledged, no body),
`ping`, `tools/list`, `tools/call`.

## Authentication (shipped)

Authenticated by an OAuth access token the platform issued to an MCP client
(`Bearer octm_at_…`, [mcp-authorization.md](./mcp-authorization.md)) or by a
tenant-scoped `oct_` API key (below) — never the browser JWT chain.

- `middleware.APIKeyAuth` resolves the key via
  `apikey.Service.AuthenticateWithPermissions` (peppered-hash lookup, legacy
  plain-hash fallback, `IsActive()` gate, active membership and account), then
  seeds tenant + optional user + permissions + `IsAdmin=false` into the request
  context. The permissions are the key's scopes narrowed to what its user holds
  now, so a demoted user's key loses the dropped scopes on the next call.
- The same authenticator instance also serves the REST API (read-only), so a
  key has one rate-limit budget across both. See [api-keys.md](./api-keys.md).
- Any failure → generic `401` (no key enumeration). Keys are never accepted in the
  query string. A JWT bearer is never treated as an API key.
- The `401` carries `WWW-Authenticate: Bearer resource_metadata=…` (OAuth
  discovery, [mcp-authorization.md](./mcp-authorization.md)), and a request
  from a browser page on a foreign `Origin` is `403` before authentication.

Mint a key with the existing JWT-gated CRUD: `POST /api/v1/api-keys` (returns the
plaintext `oct_…` once).

## Tools (shipped, all read-only)

| Tool | Backing service | Returns |
|---|---|---|
| `list_findings` | `VulnerabilityService.ListFindings` | findings (severity/status/source/search filters) |
| `get_finding` | `VulnerabilityService.GetFinding` | one finding |
| `finding_stats` | `VulnerabilityService.GetFindingStats` | totals by severity/status + KEV/EPSS/SLA rollups |
| `list_active_cves` | `VulnerabilityService.ListActiveCVEs` | KEV/EPSS-prioritized CVEs |
| `explain_finding_priority` | `PriorityClassificationService.ExplainFinding` | priority explanation (KEV/EPSS/reachability) |
| `get_exposure_chains` | `SurfaceService.GetExposureChains` | shortest attack paths to KEV/crown-jewel assets |
| `list_remediation_groups` | `GroupService.ListGroups` | solution families |
| `list_assets` | `AssetService.ListAssets` | assets (exposure/criticality/search) |
| `compliance_posture` | `ComplianceService.GetComplianceStats` | framework/control posture |

## Security model (the key invariants)

- **Tenant isolation**: the tenant is taken **solely** from the authenticated
  key's context and injected into every tool call. Tools expose **no tenant
  argument**, so a caller cannot widen scope by smuggling a `tenant_id` — a
  regression test asserts this. Every backing service takes `tenantID` explicitly
  and enforces `WHERE tenant_id = ?`.
- **Least privilege**: each tool requires a permission (`findings:read`,
  `assets:read`, `compliance:frameworks:read`) matched against the key's scopes;
  tools run with the key owner's data-scope (`IsAdmin=false`), so group scoping and
  the pentest-membership gate still apply. Mint an MCP key with the read scopes it
  needs — a scopeless key can call nothing.
- **Offboarding**: a user-scoped key stops authenticating the moment its owner's
  membership is suspended or removed.
- **Network policy**: the organization IP allowlist (`security.ip_whitelist`)
  runs right after key auth, exactly as for the same key on the REST API: a key
  used from outside the listed networks gets `403 IP_NOT_ALLOWED` on both. The
  chain is `[Origin check, 401 challenge, per-IP rate limit, key auth, IP
  allowlist]` (`routes/mcp.go`).
- **Rate limit**: a per-IP limiter runs before auth. List tools clamp to ≤100 rows.
- **Errors**: internal errors are redacted; only input-validation messages surface.

## Connecting a client

Point an MCP host at the endpoint with the key as a bearer token, e.g. a Claude
Code MCP server entry:

```json
{
  "mcpServers": {
    "openctem": {
      "type": "http",
      "url": "https://<host>/api/v1/mcp",
      "headers": { "Authorization": "Bearer oct_<key>" }
    }
  }
}
```

## Planned (not yet shipped)

- **OAuth 2.1 for MCP clients** ([RFC-062](../rfcs/RFC-062-mcp-authorization.md)):
  standard discovery (Protected Resource Metadata, `WWW-Authenticate`),
  OpenCTEM as the authorization server with its own consent page, short-lived
  tokens bound to one user, organization, client and this endpoint, read
  scopes mapped onto permissions, an organization MCP policy and a connected
  applications page. `oct_` keys stay for headless use.
- Write-capable tools, confirmed by the person in the web UI (RFC-062 §10).
- MCP `resources`; the MCP 2026-07-28 protocol revision (stateless requests).
