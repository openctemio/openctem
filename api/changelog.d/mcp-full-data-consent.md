### Added: Allow an AI application to read all organization data

- On the AI application consent page, a person whose role has full organization data access (owner, administrator, or a role with full data access) sees a new choice, "Allow access to all organization data", off by default. Turning it on needs a fresh re-authentication, is audited (`mcp_grant.full_data_allowed`, with the application's host), and the connection shows a "All organization data" badge on the organization's AI applications page and on the person's own connections.
- Such a connection reads all data only while its person still holds a full-data role: the role is checked on every request, so losing it makes the connection scoped immediately. Private program assets and pentest campaign membership follow the same rules as in the web console. `oct_` API keys never get this.
- Shorter life for these connections: 7 days in total, refresh token 24 hours unused, access token 5 minutes (scoped connections: up to 90 days, 14 days, 10 minutes).
- The person, or an organization administrator, can revoke the connection or set it back to the person's own data scope without revoking it.
- Migration `mcp_grant_full_data` adds `full_data` (default off) to MCP authorization requests and grants; existing connections are unchanged.
