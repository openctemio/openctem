# RFC-062: MCP authorization — OAuth 2.1 for AI clients

| | |
|---|---|
| Status | Accepted (owner 2026-10-08: "the most secure, modern and best design of auth for MCP"; decisions MA1–MA25 delegated) |
| Authors | Platform team |
| Related | RFC-016 (MCP server), RFC-022 (admin console), RFC-041 (API planes), RFC-050 (asset access model), RFC-057 (evidence never leaves through prompts) |
| Specification | MCP 2026-07-28 (Authorization, Authorization Server Discovery, Client Registration, Security Considerations, Streamable HTTP, Elicitation, Multi Round-Trip Requests) |
| Code | `api/internal/app/mcpoauth`, `api/internal/infra/http/handler/mcp_oauth*.go`, `api/internal/infra/http/middleware/mcp_auth.go`, `web/src/app/oauth/consent` |

## 1. Summary

Today an MCP client reaches `POST /api/v1/mcp` only with an `oct_` API key that
a person copies into the client's configuration. The key is long-lived, does
not say which application holds it, and the endpoint gives a client nothing to
discover: a `401` without `WWW-Authenticate`.

This RFC makes OpenCTEM an **OAuth 2.1 authorization server for its own MCP
endpoint**, following the MCP authorization specification (revision
2026-07-28):

- The MCP endpoint is an OAuth **protected resource**: it publishes Protected
  Resource Metadata (RFC 9728) and answers `401` with
  `WWW-Authenticate: Bearer resource_metadata=…, scope=…`.
- The API publishes **Authorization Server Metadata** (RFC 8414) and serves
  `/oauth/authorize`, `/oauth/token` and `/oauth/revoke`. The issuer is the
  public origin (`APP_URL`).
- The person signs in the normal way (password, SSO, MFA as the organization
  requires) and approves the client on an **OpenCTEM consent page** that names
  the client, its host, where the browser will be sent back, the organization
  and the permissions.
- Clients identify with **Client ID Metadata Documents** (primary), with a
  client an organization administrator **registered in advance**, or, only when
  the operator enables it, with deprecated **Dynamic Client Registration**.
- Authorization code with **PKCE S256** and **resource indicators** (RFC 8707);
  short-lived **opaque access tokens** bound to one user, one organization, one
  client and the MCP resource; **rotating refresh tokens** whose reuse revokes
  the whole grant.
- On every MCP request the token can do at most
  `permissions of its scopes ∩ what the user holds now ∩ the organization's MCP policy`,
  inside the user's own data scope.

`oct_` keys keep working for headless use; an organization can turn them off
for MCP.

## 2. Goals and non-goals

Goals: standard discovery so any compliant MCP client connects with only the
URL; tokens that cannot be used anywhere but the MCP endpoint; least privilege
by default; organizations decide which clients and permissions are allowed;
users and administrators see and revoke every connected application; every
issuance, consent and tool call audited; safe for a multi-tenant SaaS.

Non-goals (now): OpenCTEM as a general OAuth/OIDC provider for third-party
applications (only the MCP resource is served); client credentials and service
accounts; enterprise-managed authorization (identity assertion grants); write
tools (the confirmation design is fixed here, the code lands with the first
write tool).

## 3. Threat model

| Threat | Mitigation |
|---|---|
| A token issued for another service replayed at the MCP endpoint, or ours replayed elsewhere | Tokens are opaque and stored with their resource; the endpoint accepts only tokens whose resource is its canonical URI. The server never forwards a token. |
| Stolen access token | 10-minute lifetime, hashed at rest, header only (never a query parameter), checked against the database on every request so revocation is immediate; optional DPoP binding (§9). |
| Stolen refresh token | Rotated on every use; presenting an already rotated token revokes the grant and all its tokens, is audited at high severity and notifies the user. Idle 14 days, absolute 90 days, lower by policy. |
| Authorization code interception or injection | PKCE S256 required (`plain` refused); the code lives 60 seconds, is single use and bound to the client, redirect URI, challenge and resource; a second redemption revokes what the first one issued. |
| Redirect URI tampering, open redirect | Exact string match against the registered list; loopback redirect URIs may differ only in port (RFC 8252 §7.3); otherwise `https` only. Until the client and redirect URI are validated, errors are shown as a page, never redirected. |
| Consent phishing, a client impersonating another | The consent page is OpenCTEM's; it shows the client's name **and** host, the redirect host, an "unverified" mark for clients outside the organization's list and a warning for loopback-only redirect URIs. Framing is refused; approve and deny are CSRF-protected POSTs. |
| SSRF through a client metadata URL | Fetched through the platform's guarded client: `https` only, public addresses only (checked at dial time, so DNS rebinding does not help), no redirects, 5 KB, 5 seconds, errors never cached. |
| Mass registration, malicious registered clients | Dynamic registration off unless the operator enables it; when on it is rate limited, public clients only, redirect URIs loopback or `https`, unused registrations deleted after 30 days, and such clients are always "unverified". |
| Cross-tenant access | The organization is fixed at consent from the user's own memberships and stored on the grant; the endpoint takes the tenant only from the grant; tools have no tenant argument. |
| Scope escalation | The granted scopes are the requested scopes the organization allows; every request recomputes `scopes ∩ live permissions`; the owner/administrator bypass never applies to an MCP token. |
| Access outliving a role change or offboarding | Membership, account status and permissions are read live on every request; suspension or removal ends access at once. |
| Prompt injection driving tools | Read-only scopes by default; tool names and descriptions are fixed server strings; write tools need an elevated scope and a confirmation the person gives in the OpenCTEM web UI, which an agent cannot answer for them (§10). |
| Exfiltration through tool results | The user's own data scope; evidence values never enter MCP results (RFC-057); result sizes capped; per-grant rate limit; every call audited with its result size. |
| Session hijacking | MCP 2026-07-28 has no sessions; `Mcp-Session-Id` is never minted and never read for authorization. |
| DNS rebinding and browser-originated calls | The `Origin` header, when present, must be an allowed origin, else `403`. |
| Authorization server mix-up | `iss` in every authorization response (RFC 9207), advertised in metadata. |
| Abuse and brute force | Per-IP limits on the OAuth endpoints, constant-time hash lookups, per-grant limits on MCP. |

## 4. Discovery

| Document | URL | Content |
|---|---|---|
| Protected Resource Metadata | `/.well-known/oauth-protected-resource/api/v1/mcp` and `/.well-known/oauth-protected-resource` | `resource` = `${APP_URL}/api/v1/mcp`, `authorization_servers` = [`${APP_URL}`], `scopes_supported` = the read scopes, `bearer_methods_supported` = [`header`], `resource_name`, `resource_documentation` |
| Authorization Server Metadata | `/.well-known/oauth-authorization-server` | `issuer`, endpoints, `response_types_supported` [`code`], `grant_types_supported` [`authorization_code`, `refresh_token`], `code_challenge_methods_supported` [`S256`], `token_endpoint_auth_methods_supported` [`none`], `revocation_endpoint_auth_methods_supported` [`none`], `scopes_supported`, `client_id_metadata_document_supported` true, `authorization_response_iss_parameter_supported` true, `registration_endpoint` only when registration is enabled, DPoP algorithms when enabled |

A request to the MCP endpoint without a valid credential gets:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://openctem.example/.well-known/oauth-protected-resource/api/v1/mcp", scope="mcp:findings.read mcp:assets.read"
```

The issuer has no path, so clients find the AS metadata at the first
well-known location they try. The gateway gets an `oauth` plane (RFC-041) that
sends the well-known documents and the four OAuth endpoints straight to the
API; the consent page stays in the web app.

## 5. Client registration

| Kind | How the client is identified | Shown as |
|---|---|---|
| Client ID Metadata Document | `client_id` is an `https` URL with a path; the AS fetches the JSON document (guarded fetch, §3), requires `client_id` equal to the URL, `client_name`, `redirect_uris`, and accepts only public clients (`token_endpoint_auth_method: none`) | the document's name and the URL's host; "verified" when the host is on the organization's list |
| Pre-registered | an organization administrator creates the client (name, redirect URIs) and gets its `client_id` | "registered by your organization" |
| Dynamic registration (deprecated by MCP) | `POST /oauth/register`, only when the operator sets `MCP_OAUTH_DCR_ENABLED=true` | "unverified (self-registered)" |

A client of any kind is a public client: no client secrets are issued or
accepted. The platform operator can block any client.

## 6. Authorization flow

1. The client calls `GET /oauth/authorize` with `response_type=code`,
   `client_id`, `redirect_uri`, `code_challenge` (S256), `state`, `scope` and
   `resource`. The API validates the client and the exact redirect URI first;
   any failure is a page. Then it validates the rest; failures redirect with an
   OAuth error and `iss`. `resource` must equal the canonical MCP URI
   (`invalid_target` otherwise). Unknown scopes are refused; no scope means the
   read scopes.
2. The API stores the request (10 minutes, single use) and redirects to the web
   page `/oauth/consent?request=<id>`.
3. The page requires a signed-in session. Without one the person signs in
   (password, SSO, MFA as the organization requires) and comes back. The
   request is claimed by the first user who opens it.
4. The organization is the one the session is working in; the person can
   switch organization on the page, through the normal switch that applies the
   organization's SSO and MFA rules. The page shows the client, its host, the
   redirect host, warnings, the organization and the scopes in plain words.
   Scopes the organization does not allow, or that the person's permissions
   would leave empty, are shown as not granted.
5. Approve or deny (POST, CSRF). Approve creates the authorization code and the
   browser is sent to `redirect_uri?code=…&state=…&iss=…`; deny sends
   `error=access_denied`.
6. The client redeems the code at `POST /oauth/token` with `code_verifier`,
   `redirect_uri`, `client_id` and the same `resource`, and receives:

```json
{ "access_token": "octm_at_…", "token_type": "Bearer", "expires_in": 600,
  "refresh_token": "octm_rt_…", "scope": "mcp:findings.read mcp:assets.read" }
```

7. `grant_type=refresh_token` rotates the refresh token and returns a new pair;
   the scope may be narrowed, never widened.
8. `POST /oauth/revoke` (RFC 7009) revokes a token; revoking a refresh token
   revokes the grant.

Consent is shown on every authorization, including a client the person
approved before (the page says so); `prompt=none` returns `consent_required`.

## 7. Scopes and permissions

| Scope | Permissions | Tools |
|---|---|---|
| `mcp:findings.read` | `findings:read` | findings, finding stats, active CVEs, priority explanation, remediation groups |
| `mcp:assets.read` | `assets:read` | assets, exposure chains |
| `mcp:compliance.read` | `compliance:frameworks:read` | compliance posture |
| `mcp:pentest.read` | `pentest:campaigns:read`, `pentest:findings:read`, `pentest:retests:read`, `pentest:templates:read` | pentest campaigns, findings, retests, templates, report prompts |

On every request:

```
effective = permissions(granted scopes) ∩ permissions the user holds now
```

An owner or administrator holds every permission, so their token has exactly
the permissions of its scopes. The owner/administrator bypass is never set for
an MCP token. The token keeps the user's data scope: a role with full data
access sees what it sees in the web console, any other member sees the assets
their scope rows allow. (`oct_` keys keep their stricter rule: no full data
access.)

`tools/list` lists only the tools the token can run. A tool whose permission the
user holds but whose scope was not granted answers `403` with
`WWW-Authenticate: Bearer error="insufficient_scope", scope="…", resource_metadata="…"`
so the client can ask for more (step-up). A tool the user cannot run at all is
a normal tool error.

Write scopes (for example `mcp:findings.comment`) arrive with the first write tool
(§10). They are never listed in `scopes_supported`; a client gets them only
through an `insufficient_scope` challenge, and approving one requires a recent
sign-in (step-up, 10 minutes).

## 8. Organization policy

Organization settings, Security, "AI assistants (MCP)" (owner or
administrator, with step-up):

| Setting | Default | Effect |
|---|---|---|
| `enabled` | on | off: every MCP request of the organization is refused and no consent can be given |
| `clients` | `verified` | `verified`: only pre-registered clients and metadata documents whose host is in `client_hosts`; `any`: any client, unverified ones marked |
| `client_hosts` | platform default list | host names allowed for metadata documents |
| `scopes` | the four read scopes | the scopes the organization's users may grant |
| `api_keys` | on | off: `oct_` keys are refused on the MCP endpoint (still usable on the REST API) |
| `refresh_days` | 90 | absolute refresh lifetime, 1–90 |
| `require_dpop` | off | on: token requests without DPoP are refused |

Changing the policy applies on the next request: a grant outside the policy
stops working (and its scopes beyond the policy stop counting).

## 9. Tokens

| Token | Form | Lifetime | Stored |
|---|---|---|---|
| Authorization code | 256-bit random | 60 s, single use | HMAC-SHA256 with the application pepper |
| Access token | `octm_at_` + 256-bit random | 10 min | same |
| Refresh token | `octm_rt_` + 256-bit random | idle 14 d, absolute ≤ 90 d | same; rotated, the previous one kept to detect reuse |

Self-contained JWT access tokens were rejected: the resource server is the
authorization server, revocation must be immediate, and opaque tokens need no
signing-key lifecycle and carry no readable claims.

A grant records user, organization, client, resource, scopes, creation and last
use (time and IP). A grant ends when the user or an administrator revokes it,
refresh reuse is detected, the refresh lifetime ends, the client is blocked, or
the membership, user or organization is deleted. Expired rows are purged.

**DPoP (RFC 9449), optional.** When the token request carries a `DPoP` proof
(ES256 or EdDSA), the grant is bound to the key's thumbprint and the token type
is `DPoP`; every MCP request must then carry a valid proof (method, URL, time
within 60 s, unused `jti`, access-token hash). An organization can require it.

## 10. Write tools

A write tool needs: a write scope (offered only through an
`insufficient_scope` challenge, never up front), the organization policy
listing that scope (read scopes only by default), a connection a person
made (an OAuth token; `oct_` keys never run write tools), and a
confirmation from that person **outside the AI client**.

The first call validates the arguments, checks the user can reach the data
(data scope), and answers with `status: confirmation_required`, a
`confirmation_url` (`${APP_URL}/mcp/confirm/<id>`) and a `confirmation_id`;
nothing changes. The web page requires the same signed-in user in the same
organization and shows the exact action as the server describes it. After
the person confirms, the client calls the tool again with the same
arguments and the `confirmation_id`; the server runs it once if the
confirmation is approved, unexpired (5 minutes), for this connection, this
tool and the SHA-256 of these arguments, and marks it used. A confirmation
inside the client (form-mode elicitation) is not accepted as the control,
because a compromised or prompt-injected agent can answer it.

This tool-level exchange works with every MCP protocol revision. When the
endpoint moves to MCP 2026-07-28, the same confirmation is also offered as
a URL-mode elicitation in an `InputRequiredResult` (§11).

The first write tool is `add_finding_comment` (`mcp:findings.comment` →
`findings:comment`): an internal comment, never sent to integrations.

## 11. Transport

- Authorization only from the `Authorization` header; never from the body, a
  query parameter or `Mcp-Session-Id`.
- `Origin`, when present, must be the public origin or listed in
  `CORS_ALLOWED_ORIGINS`; otherwise `403`.
- Upgrading the MCP protocol itself to 2026-07-28 (stateless requests,
  `server/discover`, header checks, multi round-trip results) is separate
  work; it adds the URL-mode elicitation form of the §10 confirmation.

## 12. Visibility and audit

- **User**: Settings, Connected applications: every grant (client, host,
  organization, scopes, created, last used, IP), revoke.
- **Organization administrator**: the policy, the pre-registered clients and
  every grant in the organization, revoke.
- **Platform administrator** (console): clients across the platform (kind,
  host, grant count per organization), block a client. No tenant data.
- **Audit**: consent given or denied, token issued, refresh, refresh reuse
  (high), revocation (who and why), policy change, client registration and
  block, and every tool call with client and grant id, argument summary and
  result size.
- **Metrics**: tokens issued, refresh reuse, denied calls, calls per grant.

## 13. Decisions

| # | Decision |
|---|---|
| MA1 | The API is the authorization server; issuer = `APP_URL`; an `oauth` gateway plane. |
| MA2 | One resource, `${APP_URL}/api/v1/mcp`; the organization is chosen at consent, not in the URL. |
| MA3 | Grant types: `authorization_code` and `refresh_token` only. |
| MA4 | The person authenticates with the existing sign-in; the organization's SSO and MFA rules apply through the normal organization switch. |
| MA5 | Consent on every authorization; `prompt=none` refused. |
| MA6 | Client ID Metadata Documents first; guarded fetch; public clients only. |
| MA7 | Dynamic registration off by default (platform switch), always "unverified". |
| MA8 | PKCE S256, single-use 60-second codes, `iss` in responses, `resource` required and exact. |
| MA9 | No token passthrough. |
| MA10 | Opaque, hashed, 10-minute access tokens. |
| MA11 | Rotating refresh tokens; reuse revokes the grant. |
| MA12 | Exact redirect URIs; loopback port rule; `https` otherwise. |
| MA13 | OpenCTEM consent page with client host, redirect host and warnings; no framing; CSRF. |
| MA14 | Tenant fixed on the grant; membership, account and permissions re-read on every request. |
| MA15 | Four read scopes mapped to permissions; `insufficient_scope` step-up; write scopes only by challenge. |
| MA16 | DPoP optional, organization may require. |
| MA17 | Write tools confirmed out of band in the web UI (URL-mode elicitation), never by the client alone. |
| MA18 | Organization MCP policy (§8). |
| MA19 | Audit, metrics and per-grant limits (§12). |
| MA20 | `oct_` keys remain the headless path; no client credentials now. |
| MA21 | Enterprise-managed authorization deferred. |
| MA22 | Origin check; no session-based authorization; protocol upgrade separate. |
| MA23 | Connected applications for users, organization administrators and platform administrators. |
| MA24 | Tables for clients, authorization requests, grants and tokens; cascades and purge. |
| MA25 | An MCP token keeps the user's data scope, including full data access; `oct_` keys do not. |

## 14. Implementation

| PR | Content |
|---|---|
| 1 | Discovery documents, `oauth` plane, `WWW-Authenticate`, `Origin` check, scope catalog and `insufficient_scope` |
| 2 | Tables, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, PKCE, resource indicators, consent API and page, MCP accepts `octm_at_` tokens |
| 3 | Organization policy and its enforcement |
| 4 | Connected applications (user, organization, console) |
| 5 | Client ID Metadata Documents, pre-registered clients, dynamic registration switch |
| 6 | DPoP |
| 7 | Write-tool confirmation with the first write tool (`add_finding_comment`); URL-mode elicitation follows the protocol upgrade |

Each PR carries tests for cross-tenant use, scope escalation, token replay,
redirect URI tampering, refresh reuse and consent bypass, and is checked with a
real MCP client against a scratch deployment.
