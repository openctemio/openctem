### Added: organizations register their own AI applications

- Settings, AI access (MCP): owners and administrators register an AI
  application (MCP client) with its exact return addresses and give it the
  client id. Members see it as registered by the organization; no other
  organization can use it; deleting it ends its connections. API
  `/api/v1/mcp-access/clients` (RFC-062).
- Optional dynamic client registration (RFC 7591, `POST /oauth/register`)
  for MCP clients that support neither metadata documents nor a client id:
  off unless `MCP_OAUTH_DCR_ENABLED=true`; such applications are always
  unverified and limited to organizations that allow any application.
- A background job purges ended authorization requests, tokens, grants and
  unused clients.
- **Upgrade note:** the gateway sends `/oauth/register` to the API.
