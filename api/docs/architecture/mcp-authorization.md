# MCP authorization (OAuth 2.1 for MCP clients)

> Shipped vs planned. Design and decisions: [RFC-062](../rfcs/RFC-062-mcp-authorization.md).
> The MCP server itself: [mcp-server.md](./mcp-server.md).

OpenCTEM is the OAuth 2.1 authorization server for its own MCP endpoint,
following the MCP authorization specification (revision 2026-07-28). An MCP
client needs only the endpoint URL, `${APP_URL}/api/v1/mcp`, to find out how
to get a token.

## Identifiers

All derived from `APP_URL` (`mcpoauth.NewEndpoints`), which must be an `https`
origin with no path (plain `http` only on a loopback host):

| Name | Value |
|---|---|
| Issuer | `${APP_URL}` |
| Resource (RFC 8707, RFC 9728) | `${APP_URL}/api/v1/mcp` |
| Protected Resource Metadata | `${APP_URL}/.well-known/oauth-protected-resource/api/v1/mcp` (root fallback `/.well-known/oauth-protected-resource`) |

Without a usable `APP_URL` there is no discovery: the endpoint accepts `oct_`
keys only and a refusal carries no challenge (logged at startup).

## Discovery (shipped)

- `GET /.well-known/oauth-protected-resource/api/v1/mcp` and
  `GET /.well-known/oauth-protected-resource`: the RFC 9728 document
  (`resource`, `authorization_servers`, `scopes_supported`,
  `bearer_methods_supported: ["header"]`). Public, cacheable for 5 minutes,
  readable from any origin, rate limited per IP.
- Every `401` from `POST /api/v1/mcp` carries
  `WWW-Authenticate: Bearer resource_metadata="…", scope="…"` with the read
  scopes (`middleware.MCPChallenge`). Other statuses never carry it.
- The gateway sends `/.well-known/oauth-protected-resource*` to the API (plane
  `mcp`, generated `deploy/gateway/planes.caddy`); `next dev` rewrites it to
  the API, and the web proxy leaves `/.well-known/oauth-*` alone.

## Origin check (shipped)

`POST /api/v1/mcp` refuses (`403`) a request whose `Origin` header is present
and is neither the public origin nor one of `CORS_ALLOWED_ORIGINS`
(`middleware.MCPOriginGuard`; MCP Streamable HTTP requires servers to validate
`Origin` against DNS rebinding). Clients that are not browsers send no
`Origin` and are unaffected. `*` never opens the check.

## Scopes (shipped catalog)

`pkg/domain/mcpoauth/scope.go` is the closed list; an unknown scope is refused.

| Scope | Permissions |
|---|---|
| `mcp:findings.read` | `findings:read` |
| `mcp:assets.read` | `assets:read` |
| `mcp:compliance.read` | `compliance:frameworks:read` |
| `mcp:pentest.read` | `pentest:campaigns:read`, `pentest:findings:read`, `pentest:retests:read`, `pentest:templates:read` |

A test fails when an MCP tool or prompt needs a permission no scope covers.

## Authorization server (shipped)

| Endpoint | What it does |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata: endpoints, `code` + S256 only, grants `authorization_code` and `refresh_token`, `token_endpoint_auth_methods_supported: ["none"]` (public clients), `client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported` |
| `GET /oauth/authorize` | Validates the request and stores it for 10 minutes, then redirects to the web page `/oauth/consent?request=<id>` |
| `POST /api/v1/oauth/requests/{id}` (`GET`), `/approve`, `/deny` | Consent API for the web page: signed-in session in its current organization, CSRF; API keys refused |
| `POST /oauth/token` | `authorization_code` (with `code_verifier`, `redirect_uri`, `client_id`, `resource`) and `refresh_token` |
| `POST /oauth/revoke` | RFC 7009; a token of the presenting client revokes its whole grant; always `200` |

The gateway sends these paths to the API (plane `mcp`); the consent page
`/oauth/consent` is the web app's.

### Authorization request

Checked in this order (`mcpoauth.Service.StartAuthorization`):

1. No parameter repeated. The client is resolved (below) and the
   `redirect_uri` must match one of its registered URIs exactly; a loopback
   `http` URI may differ only in port (RFC 8252 §7.3). Any failure here is an
   error page: the browser is never sent to an untrusted address.
2. Then, with the error sent back to the redirect URI (with `state` and
   `iss`): `response_type=code`; `code_challenge_method=S256` and a 43
   character challenge (`plain` refused); `resource` equal to
   `${APP_URL}/api/v1/mcp` (scheme and host case-insensitive, trailing slash
   ignored; else `invalid_target`); `prompt=none` is `consent_required`;
   unknown scopes are `invalid_scope`; no scope means the four read scopes.

### Clients (shipped part)

- **Client ID Metadata Document**: a `client_id` that is an `https` URL with
  a path (no user info, query, fragment or dot segments). The document is
  fetched through `pkg/httpsec` (special-use addresses refused before the
  lookup and again at connection time), without following redirects, 5 KB
  and 5 seconds at most, cached for `max-age` bounded to 5 minutes..24 hours
  (default 1 hour), errors never cached. It must repeat the URL as
  `client_id`, name the client, list 1..20 redirect URIs (`https`, or `http`
  on loopback) and be a public client (no secret, `token_endpoint_auth_method`
  absent or `none`). The name is cleaned of control and bidirectional
  characters. The stored copy is in `mcp_oauth_clients`.
- **Organization clients** (`octc_…`): an owner or administrator registers
  them under Settings, AI access (MCP): a name and exact redirect URIs
  (`https`, or loopback `http` any port). `GET/POST /api/v1/mcp-access/clients`,
  `DELETE /api/v1/mcp-access/clients/{id}` (`settings:read`; changes
  `settings:write` and a recent sign-in), audited `mcp_client.registered` /
  `mcp_client.deleted`. Verified in their organization, never usable in
  another. Deleting one ends its connections.
- **Dynamic registration** (`octd_…`, RFC 7591, `POST /oauth/register`) only
  when the operator sets `MCP_OAUTH_DCR_ENABLED=true` (otherwise 404 and no
  `registration_endpoint` in the metadata). Public clients only
  (`token_endpoint_auth_method` none), grants `authorization_code` and
  `refresh_token`, response type `code`, `application_type` native or web,
  redirect URIs as above; 3 registrations a minute per address. Always
  unverified: only organizations with `any_client` can use them.
- A client with `blocked_at` set is refused everywhere, including its
  existing grants.

### Consent

The person opens `/oauth/consent?request=<id>` (signing in first if needed).
The first signed-in user who opens it claims it; nobody else can read or
answer it. The page works in the session's current organization and offers
the organization switcher, which applies that organization's SSO and MFA
rules. It shows the client name, where it is published (metadata host) or
that the organization registered it or that it is unverified, the redirect
host, a warning for loopback-only clients, and each scope in plain words;
a scope the person holds none of the permissions for is shown as not
granted. Approve stores a 60-second single-use code (hashed) and returns the
redirect with `code`, `state` and `iss`; deny returns `access_denied`.

### Tokens

| | Form | Life |
|---|---|---|
| Access token | `octm_at_` + 256 random bits | 10 minutes |
| Refresh token | `octm_rt_` + 256 random bits | 14 days unused, never past the grant |
| Grant | user + organization + client + resource + scopes | 90 days |

Codes and tokens are stored only as HMAC-SHA256 with `APP_ENCRYPTION_KEY`
(previous keys still match during a rotation). The token endpoint:

- burns the code on any mismatch (client, redirect URI, PKCE verifier) and
  checks the membership is still active before issuing;
- treats a second redemption of a code as theft: the grant the first one
  created is revoked (`mcp_grant.code_reused`, high);
- rotates the refresh token on every use; presenting a rotated one revokes
  the grant and all its tokens (`mcp_grant.refresh_reused`, high); a refresh
  may narrow the scopes, never widen them;
- answers with `Cache-Control: no-store`; parameters only in the form body;
  any `Authorization` header is `invalid_client` (no client secrets).

### MCP requests with an access token

`middleware.MCPCredentialAuth` sends `Bearer octm_at_…` to
`Service.AuthenticateAccessToken` and anything else to the `oct_` key
authenticator; both together are refused. For a token it checks, on every
request: token unexpired, grant not revoked or expired, client not blocked,
resource is this endpoint, the user still an active member with an active
account. The request then carries the grant's tenant and user, permissions
`scope permissions ∩ what the user holds now` (owners and administrators hold
everything), never the owner/admin bypass, auth provider `mcp_oauth`, and
keeps the user's own data scope including full data access (unlike `oct_`
keys). Each grant has a budget of 3600 requests per hour. Last use (time,
IP) is recorded at most once a minute.

A call the user could make with a scope the token lacks answers `403` with
`WWW-Authenticate: Bearer error="insufficient_scope", scope="…",
resource_metadata="…"` (step-up); a call no scope would allow is an ordinary
tool error.

### Audit

`mcp_grant.authorized`, `mcp_grant.denied`, `mcp_grant.token_issued`,
`mcp_grant.code_reused`, `mcp_grant.refresh_reused`, `mcp_grant.revoked`, and
every `mcp.tool_called` carries `auth_method`, `grant_id`, `client_id` and
`client_name` for token requests.

### Storage

Migration `001367_mcp_oauth`: `mcp_oauth_clients`, `mcp_oauth_requests`,
`mcp_oauth_grants`, `mcp_oauth_tokens`; grants and requests cascade on
organization and user deletion.

## Organization policy (shipped)

`GET /api/v1/mcp-access/settings` (`settings:read`) and `PUT` (`settings:write`
and a recent sign-in); API keys refused. Stored as the `mcp` section of the
organization settings (`tenant.MCPSettings`), audited as
`mcp_settings.updated` (high).

| Field | Default | Effect |
|---|---|---|
| `enabled` | on | off: every MCP request of the organization (tokens and `oct_` keys) and every consent is refused |
| `any_client` | off | off: only verified applications. Verified = registered by this organization (or by the platform operator), or a metadata document whose host is in `client_hosts` or in `MCP_OAUTH_TRUSTED_CLIENT_HOSTS`. On: any application, unverified ones marked |
| `client_hosts` | none | host names (no scheme, path or wildcard), at most 50 |
| `scopes` | all read scopes | the scopes members may grant |
| `api_keys_allowed` | on | off: `oct_` keys are `403` on the MCP endpoint (`middleware.MCPKeyPolicyGate`); still valid on the REST API |
| `refresh_days` | 90 | a connection ends this many days after the person approved it |
| `require_dpop` | off | only DPoP-bound tokens (below) |

The policy is read on every use: at consent (the page shows why an
application is blocked), at code redemption, at refresh (a connection older
than `refresh_days` or now outside the policy is revoked) and on every MCP
request (a token of a blocked application stops working; scopes the policy no
longer allows stop counting). Another organization's registered application
is never usable. A policy that cannot be read refuses the request.

## Connected applications (shipped)

| Who | Where | API |
|---|---|---|
| Everyone | My account, Connected applications (`/account/connected-apps`) | `GET /api/v1/mcp-access/my-connections`, `DELETE /api/v1/mcp-access/my-connections/{id}` |
| Owners and administrators | Settings, AI access (MCP) (`/settings/mcp`): policy and every connection of the organization, with the person | `GET /api/v1/mcp-access/connections`, `DELETE /api/v1/mcp-access/connections/{id}` (`RequireAdmin`) |
| Platform administrators | Console, System, AI applications (`/admin/system/ai-applications`): every client with active connections and organization counts (no tenant data); block or unblock (ops_admin+, audited `mcp_client.blocked` / `mcp_client.unblocked`) | `GET /api/v1/admin/mcp-clients`, `POST /api/v1/admin/mcp-clients/{id}/block`, `…/unblock` |

A row shows the application, where it is published (or that the
organization registered it, or that it is unverified), the access, when it
was connected, when and from where it was last used, and when it ends.
Disconnecting revokes the grant and deletes its tokens at once (audited
`mcp_grant.revoked` with reason `user` or `admin`). Someone else's
connection, or another organization's, answers 404. A blocked client cannot
be authorized and its tokens stop working everywhere until it is unblocked.
API keys are refused on all of `/api/v1/mcp-access`.

## Purge

The `mcp-oauth-purge` controller (hourly, one replica) deletes
authorization requests a day after they ended, expired tokens (a rotated
refresh token stays until it expires, so reuse is still caught), grants 30
days after they were revoked or expired, dynamic clients unused for 30 days
and metadata-document clients without connections not fetched for 90 days.
Blocked clients are kept.

## DPoP (shipped)

Sender-constrained tokens (RFC 9449), `pkg/dpop` and `mcpoauth/dpop.go`:

- A client that sends a `DPoP` proof (ES256 or EdDSA, `typ: dpop+jwt`,
  public `jwk`, `htm`/`htu` of the token endpoint, `iat` within 60 s, a
  unique `jti`) to `/oauth/token` gets a grant bound to the key's RFC 7638
  thumbprint (`mcp_oauth_grants.dpop_jkt`, migration `001356`) and
  `token_type: DPoP`. The proof is checked before the code is redeemed, so a
  bad proof does not burn the code.
- Refreshing a bound grant needs a proof of the same key.
- An MCP request with a bound token must use `Authorization: DPoP <token>`
  and one `DPoP` header whose proof covers `POST ${APP_URL}/api/v1/mcp` and
  the token (`ath`); a bearer token sent under the DPoP scheme, a bound
  token sent as `Bearer`, a second proof header, a replayed proof or another
  key is `401` with `WWW-Authenticate: DPoP error="invalid_dpop_proof",
  algs="ES256 EdDSA"`.
- Proof ids are remembered in Redis (`SETNX`, 2 minutes) across replicas;
  without the cache proofs are refused (fail closed).
- Organization policy `require_dpop` refuses code exchanges without a proof
  and stops existing bearer connections at once.
- Metadata: `dpop_signing_alg_values_supported` in both documents,
  `dpop_bound_access_tokens_required: false` in the resource metadata.

## Planned

Write-tool confirmation: see RFC-062 §10 and §14.
