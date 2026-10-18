### Security: the modules list can no longer be served from another user's browser cache

- `GET /api/v1/me/modules` answered `304 Not Modified` to any request whose ETag matched the
  tenant's first eight id characters and two small version counters, so on a shared browser profile
  a second user could be shown the first user's module and permission payload. The ETag is now an
  HMAC under a server secret (derived from the session secret) over the tenant, the user, the admin
  flag and both versions, compared in constant time, and the response carries
  `Vary: Authorization, Cookie` next to `Cache-Control: private`.
