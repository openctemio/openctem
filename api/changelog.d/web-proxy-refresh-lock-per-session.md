### Security: the web API proxy never shares one person's refreshed session with another

- The web server's `/api/v1` proxy refreshed expired access tokens behind a lock keyed by the organization id from the `app_tenant` cookie. A request that arrived while another member's refresh was in flight received that member's new access token and rotated refresh token as its own cookies. The tenant cookie is set by the client, so anyone who knew an organization id could collect a signed-in member's session by sending requests with a made-up refresh cookie; two members of one organization whose tokens expired together could also swap sessions.
- The lock is now keyed by the caller's own refresh token (with the organization), so only parallel requests of one session share a refresh.
