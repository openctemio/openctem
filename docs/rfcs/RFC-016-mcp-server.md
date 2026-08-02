# RFC-016 — Read-only MCP server (AI-native access to CTEM data)

> Status: **Phase 1 shipped** (tenant-scoped API-key auth + read-only MCP server)
> Origin: a deep-dive of `oasm-platform/open-asm` — the one capability it had that
> OpenCTEM genuinely lacked was a first-class **Model Context Protocol** server.

## Problem

OpenCTEM's value is a richly-correlated dataset: findings with KEV/EPSS, attack-
path exposure chains, remediation groups (solution families), compliance posture,
and asset exposure. That is exactly the shape of data an AI assistant reasons over
well — but there was no way for an AI client (Claude Desktop/Code, or any MCP
host) to query it. OASM ships an MCP server; we shipped nothing.

## Non-integration decision

We evaluated running OASM alongside OpenCTEM. Rejected: OASM's modules
(discovery, scanning, ingest, findings, workflows, RBAC) map onto capabilities we
already have and surpass, and a second platform would duplicate our agent/scan/
ingest plane and create a second system-of-record — the trap RFC-013 already
rejected. We adopt the **idea** (MCP), not the platform.

## Enabling gap

An MCP client presents a *static, tenant-scoped bearer token* — neither the
browser JWT+CSRF flow nor the cross-tenant agent-key flow. OpenCTEM already had
the right primitive, the tenant-scoped `oct_` **api_keys** domain (entity, CRUD,
hashed storage, repo `GetByHash`), but no authentication path — an explicit
unfinished "F-9 follow-up". Phase 1 completes it.

## Design

### Phase 1a — API-key authentication (security-critical)
- `apikey.Service.Authenticate(ctx, rawKey, ip)` — peppered-hash lookup with a
  legacy plain-SHA256 fallback; `IsActive()` gate; best-effort last-used
  telemetry; one generic `ErrAPIKeyNotFound` for every failure (anti-enumeration).
- `middleware.APIKeyAuth` — `Authorization: Bearer oct_…` / `X-API-Key`; seeds the
  same context as the JWT path (tenant, optional user, scopes-as-permissions,
  `IsAdmin=false`); generic 401; never reads a key from the query string; a JWT
  bearer is never probed as a key.

### Phase 1b — Read-only MCP server
- **Transport**: hand-rolled minimal MCP over stdlib — JSON-RPC 2.0 at a single
  endpoint `POST /api/v1/mcp`, `application/json` responses. No SSE (the codebase
  uses WebSocket for realtime; request/response tools don't need it) and **no new
  dependency**. The official Go SDK is a future option if we add resources/prompts/
  streaming.
- **Methods**: `initialize`, `notifications/*` (ack, no body), `ping`,
  `tools/list`, `tools/call`.
- **Auth/scope**: gated solely by `APIKeyAuth`. The tenant comes only from the
  authenticated key and is injected into every tool call — a caller cannot widen
  scope via tool arguments (there is no tenant argument). Read-only by
  construction; no write tools exist.
- **Tools** (each reuses an existing tenant-scoped read service): `list_findings`,
  `get_finding`, `finding_stats`, `list_active_cves` (KEV/EPSS), `explain_finding_
  priority`, `get_exposure_chains`, `list_remediation_groups`, `list_assets`,
  `compliance_posture`.

## Security properties (hardened after an adversarial review)

- **Tenant isolation**: every tool is confined to the authenticated key's tenant;
  a test asserts a smuggled `tenant_id` argument is ignored.
- **Least privilege**: each tool declares a required permission and is gated by the
  same `HasPermission` check the REST routes use — a key can call a tool only if it
  carries that scope. Tools run with the key owner's **data-scope** (`ActingUserID`,
  `IsAdmin=false`), never an admin-wide view, so group data-scoping and the
  pentest-membership gate still apply.
- **Offboarding**: `Authenticate` gates a user-scoped key on an **active
  membership** (`MembershipChecker`), so suspending/removing a member revokes their
  key immediately — fail-closed on any lookup miss/error.
- **DoS**: a per-IP rate limiter runs before auth; list tools clamp result size
  (default 25, max 100); the global 10 MB body limit + concurrency limit apply.
- **Info leak**: only safe input-validation messages are returned verbatim; any
  internal/service error is redacted to "tool execution failed" and logged
  server-side. Errors never echo attacker-controlled input.

## Follow-ons

- **Phase 2 (UI)**: a settings page to mint an MCP key + show the Claude connection
  config.
- **Phase 3**: per-key rate limiting (the key carries `RateLimit()`); optional
  scope enforcement (`mcp:read`); write-capable tools behind explicit scopes;
  `resources`/`prompts` (would justify adopting the official Go SDK).

## Files

| Concern | Path |
|---|---|
| API-key auth | `internal/app/apikey/service.go` (`Authenticate`), `internal/infra/http/middleware/apikey_auth.go` |
| MCP protocol | `internal/infra/http/handler/mcp_handler.go` |
| MCP tools | `internal/infra/http/handler/mcp_tools.go` |
| Route | `internal/infra/http/routes/mcp.go` (`POST /api/v1/mcp`) |
| Architecture | `docs/architecture/mcp-server.md` |
