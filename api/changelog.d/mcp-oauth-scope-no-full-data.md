### Security: MCP OAuth tokens never get the holder's full-data role

- A request authenticated with an MCP OAuth access token is now treated like an API key on every data-scope path (findings list, query endpoint, web endpoints, and the shared data-scope enforcer): it reads only what the user's scope rows allow, even when the user holds a full-data role such as Owner or Administrator in a session. The token's granted scopes still bound its permissions. Before, only API keys were narrowed, so an MCP connection of an administrator read every finding of the organization.
