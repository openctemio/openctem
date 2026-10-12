### Removed: AUTH_ACCESS_TOKEN_COOKIE_NAME, AUTH_REFRESH_TOKEN_COOKIE_NAME, AUTH_TENANT_COOKIE_NAME

- The session cookies are always `auth_token`, `refresh_token` and `app_tenant`, the names the web console and the gateway use. A custom name reached the API only, which split the session between the three.
- Startup refuses the three variables with a hint. **Upgrade note:** delete them from your environment if set.
