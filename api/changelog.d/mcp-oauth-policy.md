### Security: organizations decide which AI applications may connect

- New organization MCP policy (RFC-062): `GET`/`PUT /api/v1/mcp-access/settings`
  (`settings:read`, `settings:write` with a recent sign-in). It turns MCP off
  for the organization, limits applications to verified ones (registered by
  the organization or published on a listed host) unless `any_client` is on,
  caps the scopes members may grant, turns `oct_` keys off on the MCP
  endpoint, and shortens how long a connection lasts (1 to 90 days).
- The policy applies at consent, at token issue and refresh, and on every
  MCP request, so a change takes effect immediately for existing
  connections. Changes are audited (`mcp_settings.updated`).
- `MCP_OAUTH_TRUSTED_CLIENT_HOSTS` lists the hosts every organization treats
  as verified.
- **Behaviour change:** by default only verified applications can be
  connected; an application published on another host needs its host listed
  by the organization (or `any_client`).
