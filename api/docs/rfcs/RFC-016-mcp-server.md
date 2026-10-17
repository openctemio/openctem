# RFC-016 — Read-only MCP server (AI-native access to CTEM data)

> Status: **Phase 1–2 shipped, Phase 3 partial** (checked 2026-10-12): tenant-scoped API-key auth + read-only MCP server (#299, hardened in #323); 15 read tools and 4 report prompts (#324); the connect page (openctemio/ui#234); per-key rate limits enforced (#556); the same keys read the REST API (#667); OAuth connections and the first confirmed write tool (RFC-062); pentest reads made report-consistent, paged, typed and marked untrusted, with campaign discovery and a TLP limit for AI applications (§ Pentest reads). Not built: draft-first pentest write tools, MCP resources, the current protocol revisions.

## Problem

OpenCTEM's value is a richly-correlated dataset: findings with KEV/EPSS, attack-
path exposure chains, remediation groups (solution families), compliance posture,
and asset exposure. That is exactly the shape of data an AI assistant reasons over
well — but there was no way for an AI client (Claude Desktop/Code, or any MCP
host) to query it.

## Non-integration decision

AI access is served by OpenCTEM itself, not by running a second asset-management
platform alongside it: a second platform would duplicate our agent/scan/ingest
plane and create a second system-of-record — the trap RFC-013 already rejected.

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
- **Info leak**: errors are typed (`invalid_argument`, `not_found`, `forbidden`,
  `permission_denied`, `module_disabled`, `unavailable`, `internal_error`) with a
  safe message; "absent" and "not readable" share one `not_found` answer, and an
  internal error returns no detail (it is logged server-side).
- **Result guard**: every tool result and prompt data message is cleaned of hidden
  characters (bidi, zero-width, tag characters), has secrets redacted, and is
  capped per field and per result (`result_too_large`). See
  `architecture/mcp-server.md`.
- **Rule for every new tool**: use the scoped service path (tenant from context,
  acting user, data scope); return tenant text only through `untrustedResult`;
  fetch only through `pkg/httpsec`; never approve, accept a risk, approve a false
  positive, delete, launch a scan or change integration configuration. A tool may
  create an approval request through the transition engine; it never decides one.
  A new write tool must be added to the write-tool allowlist test with its
  security review note.

## Pentest reads

The pentest tools and prompts (campaign context, findings, retests,
templates, report prompts) follow the campaign role with no administrator
bypass, and four rules keep them correct for an AI client:

1. **Report-consistent prompts.** `exec_summary` and `attack_narrative` read
   the delivered report's selection (published findings only: no drafts,
   findings under review, false positives or duplicates) and count their
   statistics from it.
2. **Untrusted content.** Tool results that carry text written by people or
   imported from tested systems return it under `untrusted_data` with a fixed
   notice, as the prompts' DATA message does; descriptions and the server
   instructions state the rule.
3. **Paging in SQL.** `list_campaign_findings` filters by severity, status and
   search in SQL before paging (`page`, `limit` ≤ 50, `has_more`); nothing is
   cut at a fixed row count before filtering.
4. **Annotations, typed errors, consistent arguments.** Every tool carries
   `readOnlyHint`/`destructiveHint`; ids are `campaign_id` and `finding_id`;
   the rules of engagement's contact and escalation details reach the
   campaign lead only.

5. **Discovery.** `list_campaigns` (the person's campaigns with role, phase,
   counts and next action) and `my_work` (the campaigns where the role has
   something to do) replace pasting ids; membership is a SQL filter and a
   client gets published counts only.

6. **TLP limit.** The organization sets the most restrictive TLP AI
   applications may read (`max_tlp`, default amber, RFC-062 §8) and a campaign
   lead can turn AI assistants off for one campaign; every pentest tool and
   prompt refuses such a campaign with `campaign_restricted` after the
   membership check, and lists leave it out.

Details: [mcp-server.md](../architecture/mcp-server.md).

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
