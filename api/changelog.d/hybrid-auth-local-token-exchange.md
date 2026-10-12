### Fixed: switching organizations works with AUTH_PROVIDER=hybrid

- In hybrid mode `POST /api/v1/auth/token` was answered by a deprecated OIDC
  stub (200 with an identity-provider URL and no token) instead of the local
  tenant token exchange, so a local user could not switch organizations. The
  local exchange now serves the route in local and hybrid mode.

### Removed: the OIDC `POST /api/v1/auth/token` stub

- With `AUTH_PROVIDER=oidc` the route no longer exists (404): the identity
  provider issues tokens, and the stub never issued one. `GET /api/v1/auth/info`
  still returns the provider endpoints.
