### Security: the sign-in routes refuse writes a browser sends for another site

- `POST /api/v1/auth/register`, `/login`, `/mfa/verify`, `/mfa/enroll/*`,
  `/token`, `/refresh`, `/verify-email`, `/forgot-password`,
  `/reset-password`, `/create-first-team`, `/discover`, the OAuth and SSO
  callbacks, and the console's `/api/v1/admin/auth/session`, `/mfa`,
  `/logout`, `/idp/start` and `/idp/callback` answer 403 when the browser
  says the request comes from another site: an `Origin` that is neither the
  request's host nor in `CORS_ALLOWED_ORIGINS`, `Origin: null`, or no
  `Origin` and `Sec-Fetch-Site` other than `same-origin`/`none`. These routes
  run before a session exists and set session cookies, so without the check a
  page on another site could sign a visitor into the attacker's account
  (login CSRF) where the API is reachable from browsers directly.
- Calls that send neither header (the web console's server, scripts, CI) are
  not affected. Rejections count in `csrf_rejections_total{reason="cross_site"}`.
