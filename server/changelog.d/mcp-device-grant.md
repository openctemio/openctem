### Added: sign an AI assistant in from a remote terminal with a code

- MCP clients running where the browser is not (an SSH session, a container, a remote desktop) can now sign in with the OAuth device authorization grant (RFC 8628): the terminal shows a short code, the person enters it at `/oauth/device` in any signed-in browser and approves on the usual consent page, which shows the address and user agent the terminal asked from. Endpoint `POST /oauth/device_authorization`, grant type `urn:ietf:params:oauth:grant-type:device_code` at `POST /oauth/token`, both advertised in the authorization server metadata. The platform's terminal client is `octc_terminal`; an organization's own registered clients work too, in that organization only.
- Approving needs a recent sign-in; such a connection never reads all organization data and is listed as a terminal sign-in under Connected applications.
- New organization policy switch `device_flow_allowed` (on by default) under AI assistants (MCP): off refuses new codes and stops existing terminal connections.
- Migration `mcp_oauth_device_grant`: new columns on `mcp_oauth_requests` and `mcp_oauth_grants` (constant defaults, no rewrite) and the `octc_terminal` client row.

### Security: terminal sign-in codes resist phishing and guessing

- The person must type the user code (no pre-filled link), codes expire after 10 minutes, a code belongs to the first person who enters it, entering codes is limited per address and per person, a device request cannot be opened by its id, a device code works only for its client and a replayed one revokes the connection it created.
