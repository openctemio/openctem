# MCP server (AI access to CTEM and pentest data)

> Shipped vs planned. Rationale: [RFC-016](../rfcs/RFC-016-mcp-server.md);
> authorization, organization policy and write tools:
> [RFC-062](../rfcs/RFC-062-mcp-authorization.md) and
> [mcp-authorization.md](./mcp-authorization.md).

OpenCTEM exposes a **Model Context Protocol** server so an AI client (a
desktop or IDE assistant, or any MCP host) can read an organization's CTEM
data and the pentest campaigns of the signed-in person, and draft report
sections from them. It reuses the tenant-scoped read services: no new data
path. One write tool exists (`add_finding_comment`); it runs only after the
person confirms the exact action in the web UI.

## Endpoint

```
POST /api/v1/mcp
Authorization: Bearer octm_at_<token>   (OAuth, a person's connection)
Authorization: Bearer oct_<api-key>     (a tenant API key)
Content-Type: application/json
```

JSON-RPC 2.0. A single request/response per POST (`application/json`); no SSE.
Methods: `initialize`, `notifications/*` (acknowledged, no body), `ping`,
`tools/list`, `tools/call`, `prompts/list`, `prompts/get`. The server
advertises protocol revision `2024-11-05`; tool annotations (below) are sent
as well, and clients that predate them ignore them.

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
plaintext `oct_…` once). Pentest tools need a key with an owning user.

## Tools (shipped)

Every tool requires a permission matched against the credential's scopes and
is listed only to credentials that hold it. Every tool carries annotations:
read tools `readOnlyHint: true, idempotentHint: true`, the write tool
`readOnlyHint: false`; all `destructiveHint: false, openWorldHint: false`.

| Tool | Permission | Returns |
|---|---|---|
| `list_findings` | `findings:read` | findings (severity/status/source/search filters), caller's data scope |
| `get_finding` (`finding_id`) | `findings:read` | one finding |
| `finding_stats` | `findings:read` | totals by severity/status + KEV/EPSS/SLA rollups |
| `list_active_cves` | `findings:read` | KEV/EPSS-prioritized CVEs |
| `explain_finding_priority` (`finding_id`) | `findings:read` | priority explanation (KEV/EPSS/reachability) |
| `get_exposure_chains` | `assets:read` | shortest attack paths to KEV/crown-jewel assets |
| `list_remediation_groups` | `findings:read` | solution families |
| `list_assets` | `assets:read` | assets (exposure/criticality/search) |
| `compliance_posture` | `compliance:frameworks:read` | framework/control posture |
| `list_campaigns` | `pentest:campaigns:read` | the person's campaigns, newest first: role, phase, TLP, dates, counts, next action; `phase`, `role`, `search`, `include_archived` filters, paged |
| `my_work` | `pentest:campaigns:read` | the person's active campaigns with something to do (drafts, assigned findings, reviews, retests; for a client, open published findings), with the next action, paged |
| `get_campaign` (`campaign_id`) | `pentest:campaigns:read` | campaign context: scope, rules of engagement, methodology, objectives, team (names and roles), TLP, phase |
| `list_campaign_findings` | `pentest:findings:read` | a campaign's findings with report fields; `severity`, `status`, `search` filters and `page`/`limit` paging |
| `get_pentest_finding` (`finding_id`) | `pentest:findings:read` | one pentest finding; evidence as counts only |
| `list_retests` | `pentest:retests:read` | a campaign's retests, newest first, paged |
| `list_finding_templates` | `pentest:templates:read` | the finding template library |
| `campaign_report_stats` | `pentest:campaigns:read` | working counts (drafts and findings under review included) |
| `add_finding_comment` (write) | `findings:comment` | a comment, after the person confirms it ([RFC-062 §10](../rfcs/RFC-062-mcp-authorization.md)) |

Tools that took `id` take `campaign_id` or `finding_id` like the others; `id`
is still accepted.

### Pentest tools

- **Membership, no administrator bypass.** Every pentest tool acts for the
  credential's person with `IsAdmin=false`: a tenant administrator who is not
  a member of a campaign reads nothing of it, and a key without a person is
  refused. Campaign-wide tools (`get_campaign`, `list_campaign_findings`,
  `list_retests`, `campaign_report_stats`, the campaign prompts) are for the
  team: a client gets `not_found` from them. A client reads a published
  finding of their campaign with `get_pentest_finding` (drafts and findings
  under review do not exist for them, in SQL and again in the handler).
- **Discovery.** `list_campaigns` and `my_work` list only the campaigns the
  person is a member of (a SQL membership filter, tenant-scoped; being a
  tenant administrator adds nothing), with `my_role`, the phase and its label
  (Planning, Testing, Reporting, Remediation, On hold, Canceled, Closed), and
  a `next_action` computed from the role, the phase and the counts. Counts
  are `published` (by severity, as the report counts them: no drafts,
  findings under review, false positives or duplicates), `open_published`
  and `awaiting_retest`; team roles also get `drafts`, `in_review`,
  `my_drafts` and `assigned_to_me`, a client never does
  (`unpublished_hidden: true`). `my_work` scans the active phases (planning,
  testing, reporting, remediation; at most 500 campaigns) and keeps those
  with work for the role: an observer never has any.
- **Rules of engagement.** `get_campaign` sends a whitelist: testing hours,
  allowed and restricted methods and data handling to every team member; the
  emergency contact, communication channel and escalation procedure to the
  campaign lead only. Other keys are dropped.
- **Paging and filters.** `list_campaign_findings` pushes `severity` (one or
  a list), `status` (one or a list of the pentest statuses) and `search`
  (title and description, ≤ 200 characters) into SQL before paging, so
  `total` is the filtered count. `page` starts at 1, `limit` is 1–50
  (default 25); the result carries `has_more` and `next_page`.
  `list_retests` pages the same way.
- **Evidence** is never returned: counts and a `has_poc` flag only; no PoC,
  request/response bodies or files.

### TLP limit for AI applications

Sending campaign content to an AI application hands it to the model provider
behind that application, which a TLP:RED engagement typically does not allow.

- **Organization policy** `max_tlp` (Settings, AI access (MCP), organization
  policy; `GET/PUT /api/v1/mcp-access/settings`, `settings:write` and a
  recent sign-in to change; audited with the before/after values, high): the most restrictive TLP of a campaign AI applications may read,
  `clear`, `green`, `amber` (default), `amber_strict` or `red`.
- **Campaign switch** `ai_assistants_disabled` (campaign Engagement card; the
  campaign update, lead only; audited `campaign.ai_access_changed`, high): the
  lead keeps one campaign away from AI applications whatever its TLP. It can
  only narrow the organization policy, never widen it.
- **Enforcement.** After the membership check (a non-member still gets
  `not_found`), every pentest tool and prompt that would carry a restricted
  campaign's content refuses with `campaign_restricted` and says why (the
  campaign's TLP and the organization limit, or the lead's switch):
  `get_campaign`, `list_campaign_findings`, `get_pentest_finding`,
  `list_retests`, `campaign_report_stats`, the four prompts, the generic
  `get_finding` and `explain_finding_priority` on a pentest finding, and
  `add_finding_comment` (before the confirmation and again when it runs).
  `list_campaigns` and `my_work` leave restricted campaigns out in SQL and
  return `restricted_hidden` (a count, no names). The generic `list_findings`
  leaves their findings out in SQL. A policy that cannot be read refuses
  (`internal_error`). `finding_stats` counts stay tenant-wide (numbers only).

### Untrusted content

Text in tool results was written by people or imported from tested systems
(scanner output reflects the target's responses), so a finding title can try
to instruct the model. Every tool whose result carries free text returns it
under `untrusted_data`, next to a fixed `notice` that tells the model to treat
it as data, the same rule the prompts state in their DATA message; ids,
paging and the caller's role sit beside it. The tool descriptions and the
server `instructions` say so too. Write actions cannot be triggered by such
text: they need the person's confirmation outside the AI client.

**Result guard.** One guard (`handler/mcp_guard.go`) runs on every tool result
and every prompt DATA message, so a new tool cannot forget it:

- hidden text is removed: bidirectional controls, zero-width characters,
  Unicode tag characters (invisible ASCII), invisible math operators and C0/C1
  controls (`safetext.Clean`), so the model reads what a person would read;
- secrets are redacted (`safetext.RedactSecrets`: cloud keys, tokens, JWTs,
  private key blocks, `password=` values);
- each string is capped by field kind (titles and names 240 characters,
  narrative fields such as descriptions, steps, impact and notes 16,000, all
  others 1,024); a cut field ends with `…`;
- one result or prompt message is capped at 256 KB; a larger one is the typed
  error `result_too_large`, asking for a smaller `limit` or a narrower filter.

`explain_finding_priority` (rule names and reasons are written by people in the
organization) is wrapped like every other tool that carries free text.

### Errors

A failed call is a normal result with `isError: true` and JSON text
`{"error": {"code", "message", "retryable"}}`; a failed `prompts/get` is a
JSON-RPC error whose message starts with the code.

| Code | When |
|---|---|
| `invalid_argument` | a missing or malformed argument, an unknown status or severity; the message names it |
| `not_found` | the item does not exist **or** the caller may not read it (one answer, so existence is never confirmed) |
| `forbidden` | the campaign role does not allow the action |
| `permission_denied` | the credential lacks the tool's permission (OAuth connections also get an `insufficient_scope` step-up challenge) |
| `module_disabled` | the organization has the tool's module off |
| `not_confirmed` | a write call whose confirmation is missing, refused, expired, used or for other arguments |
| `campaign_restricted` | the campaign is above the organization's TLP limit for AI applications, or its lead turned AI assistants off |
| `unavailable`, `internal_error` | a timeout or a server fault; `retryable: true`; no internal detail is returned (it is logged) |

## Prompts (shipped)

`exec_summary` and `attack_narrative` (`campaign_id`, `pentest:campaigns:read`),
`finding_writeup` and `remediation_guidance` (`finding_id`,
`pentest:findings:read`). Each returns an instruction message and a separate
DATA message holding the context as fenced JSON, marked untrusted.

The two campaign prompts use the delivered report's selection
(`PentestService.ReportFindings`): published findings only, no drafts,
findings under review, false positives or duplicates, most severe first; the
statistics are counted from the same set, so the AI-drafted summary and the
report agree. `attack_narrative` carries at most 100 findings and says when it
cut.

## Security model (the key invariants)

- **MCP requests, never decides**: no tool approves, rejects, accepts a risk,
  approves a false positive, deletes, launches a scan or changes an integration.
  A write tool only creates a request that the person confirms in the web
  console (four-eyes stays there). Tests keep this true: the set of write tools
  is an allowlist that needs a security review note to extend, no tool name may
  look like a decision, and `tools/list` is identical for every organization
  (tool definitions never carry tenant data).
- **Confirmation text**: the text shown on the confirmation page is cleaned of
  hidden characters when stored and again when shown, and a comment containing
  hidden characters is refused (`invalid_argument`), so what the person approves
  is exactly what is stored.

- **Tenant isolation**: the tenant is taken **solely** from the authenticated
  credential and injected into every tool call. Tools expose **no tenant
  argument**, so a caller cannot widen scope by smuggling a `tenant_id` — a
  regression test asserts this. Every backing service takes `tenantID` explicitly
  and enforces `WHERE tenant_id = ?`.
- **Least privilege**: tools run with the person's data scope (`IsAdmin=false`),
  so group scoping and the pentest-membership gate still apply. A scopeless key
  can call nothing.
- **Offboarding**: a user-scoped key stops authenticating the moment its owner's
  membership is suspended or removed.
- **Network policy**: the organization IP allowlist (`security.ip_whitelist`)
  runs right after key auth, exactly as for the same key on the REST API: a key
  used from outside the listed networks gets `403 IP_NOT_ALLOWED` on both. The
  chain is `[Origin check, 401 challenge, per-IP rate limit, key auth, IP
  allowlist]` (`routes/mcp.go`).
- **Rate limit**: a per-IP limiter runs before auth, and a per-credential budget
  after it. The budget's burst is capped at 60 requests (the hourly rate is
  unchanged), so a hijacked assistant cannot spend a whole hour in one burst. Generic list tools clamp to ≤100 rows, pentest lists to ≤50 per page.
- **Audit**: every `tools/call` and `prompts/get` (success, denied, failure) is
  audited with the tool, ids and enum arguments (free text such as `search` is
  recorded as redacted), result size, user, IP and the OAuth client.

## Connecting a client

Connect from the AI client with OAuth (the client discovers the authorization
server from the `401`), or point an MCP host at the endpoint with a key as a
bearer token:

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

## Key files

| Concern | Path |
|---|---|
| Protocol, dispatch, audit | `internal/infra/http/handler/mcp_handler.go` |
| Generic tools | `internal/infra/http/handler/mcp_tools.go` |
| Pentest tools | `internal/infra/http/handler/mcp_pentest_tools.go`, `mcp_pentest_discovery.go` |
| Results envelope, typed errors | `internal/infra/http/handler/mcp_results.go` |
| TLP limit for AI applications | `internal/infra/http/handler/mcp_ai_policy.go`, `pkg/domain/tenant/mcp_settings.go` (`MaxTLP`), `pentest_campaigns.ai_assistants_disabled` (migration 002074) |
| Prompts | `internal/infra/http/handler/mcp_prompts.go` |
| Write tools | `internal/infra/http/handler/mcp_write_tools.go` |
| Pentest queries (member-scoped paging, report selection, member campaigns) | `internal/app/compliance/pentest_queries.go`, `internal/infra/postgres/pentest_campaign_stats.go` (`GetWorkCountsByIDs`) |

## Planned (not yet shipped)

- Draft-first pentest write tools (create drafts, evidence, checklist, retests)
  with one confirmation per batch.
- The current MCP protocol revisions: structured output with output schemas,
  resource links, `resources`, and the 2026-07-28 stateless requests with the
  write confirmation as a URL-mode elicitation.
