### Changed: one session read per page load instead of six

- `GET /me/bootstrap` now also returns the caller's profile (`user`, as
  `/users/me`), their organizations (`tenants`, as `/users/me/tenants`), the
  organization policy (`tenant_creation_mode`, as `/auth/providers`) and the
  badge counts (`badges.unread_notifications`, `badges.easm_review`). Each part
  is the caller's own data; the review count is data-scoped and only sent with
  `assets:read` and the attack surface module, like `/easm/candidates`.
- The web console reads these from the bootstrap instead of asking each
  endpoint on every page load, so a hard load of any page sends five fewer
  requests, and `/auth/providers` (which shares the sign-in rate limit) is only
  asked on the sign-in pages.
- The bootstrap response is `Cache-Control: private, no-store`.
