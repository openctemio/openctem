### Added: MCP clients discover how to authenticate

- `POST /api/v1/mcp` answers a missing or invalid credential with
  `WWW-Authenticate: Bearer resource_metadata=…, scope=…`, and the API serves
  the OAuth Protected Resource Metadata of the MCP endpoint (RFC 9728) at
  `/.well-known/oauth-protected-resource/api/v1/mcp` and
  `/.well-known/oauth-protected-resource` (RFC-062). The resource and issuer
  come from `APP_URL`; without it nothing changes.
- **Upgrade note:** the gateway sends `/.well-known/oauth-protected-resource*`
  to the API; update a custom reverse proxy the same way.

### Security: the MCP endpoint checks the Origin header

- A request to `POST /api/v1/mcp` from a browser page whose `Origin` is not
  the public origin or one of `CORS_ALLOWED_ORIGINS` is refused with `403`.
  Clients that are not browsers send no `Origin` and are unaffected.
