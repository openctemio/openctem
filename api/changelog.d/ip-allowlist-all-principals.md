### Security: the organization IP allowlist binds MCP OAuth and OIDC tokens

- The IP allowlist (Settings, Authentication) now applies to every request that acts as an organization member, whatever the credential: a session, an `oct_` API key, an MCP OAuth access token, or an OIDC token. Before, MCP OAuth access tokens on `POST /api/v1/mcp` and OIDC tokens passed the allowlist from any address. They now get `403 IP_NOT_ALLOWED` from outside the listed networks.
- Sensor keys, SCIM, inbound webhooks and the platform admin console stay outside the allowlist, as before.
- **Upgrade note:** an organization with an allowlist whose MCP clients (connected assistants) run outside the listed networks must add those addresses, or the connection is refused.
