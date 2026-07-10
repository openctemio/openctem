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

Authenticated **only** by a tenant-scoped `oct_` API key — never the browser JWT
chain, because an MCP client presents a static bearer token.

- `middleware.APIKeyAuth` resolves the key via `apikey.Service.Authenticate`
  (peppered-hash lookup, legacy plain-hash fallback, `IsActive()` gate), then
  seeds tenant + optional user + scopes-as-permissions + `IsAdmin=false` into the
  request context.
- Any failure → generic `401` (no key enumeration). Keys are never accepted in the
  query string. A JWT bearer is never treated as an API key.

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

- UI settings page to mint an MCP key + show this connection block (Phase 2).
- Per-key rate limiting (the key carries `RateLimit()`), optional `mcp:read` scope
  enforcement, write-capable tools behind explicit scopes.
- MCP `resources`/`prompts` — would justify adopting the official Go MCP SDK.
