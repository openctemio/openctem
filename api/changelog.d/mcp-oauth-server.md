### Added: AI applications connect to the MCP server with OAuth

- OpenCTEM is now the OAuth 2.1 authorization server of its MCP endpoint
  (RFC-062): authorization server metadata, `/oauth/authorize`,
  `/oauth/token`, `/oauth/revoke`, and a consent page (`/oauth/consent`)
  where a signed-in person sees the application, where it is published, where
  the browser returns, the organization and the access, and approves or
  refuses. An MCP client needs only the endpoint URL.
- Authorization code with PKCE S256 and a resource indicator; applications
  identify with a Client ID Metadata Document (fetched without redirects,
  public addresses only) or a client registered in advance.
- Access tokens last 10 minutes and are bound to one person, one
  organization, one application and the MCP endpoint; refresh tokens rotate,
  and presenting a used one revokes the connection. On every request the
  token can do at most what its scopes allow and the person still holds;
  suspension or removal ends it at once. A call another scope would allow
  gets an `insufficient_scope` challenge.
- Every consent, token issue, reuse and revocation is audited; tool-call
  audit rows name the application and connection.
- Migration `001381_mcp_oauth`.
- **Upgrade note:** the gateway sends `/.well-known/oauth-authorization-server`
  and `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` to the API; update a
  custom reverse proxy the same way. `APP_URL` must be the public `https`
  origin. `oct_` keys keep working.
