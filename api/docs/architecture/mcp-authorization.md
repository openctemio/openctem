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

## Planned

Authorization server endpoints and consent, organization policy, connected
applications, client registration (Client ID Metadata Documents, organization
clients, optional dynamic registration), DPoP, write-tool confirmation: see
RFC-062 §14.
