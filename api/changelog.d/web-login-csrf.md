### Security: the web console checks CSRF on every write, before sign-in too

- Every POST, PUT, PATCH and DELETE the web server answers must come from the
  console's own origin (`Sec-Fetch-Site`, `Origin`, else `Referer`; a request
  with neither is refused) and echo the `csrf_token` cookie in `X-CSRF-Token`.
  Otherwise it gets `403 CSRF_INVALID` and nothing runs. Before, the web
  routes let a request through when it had no `csrf_token` cookie, and the
  `/api/v1` proxy checked nothing itself, so a page on another site could
  sign a visitor into the attacker's account (login CSRF) through
  `/api/v1/auth/login`.
- The pre-session steps are covered: sign-in, registration, forgot, reset and
  set password, invitation acceptance, second-factor steps, team selection
  and SSO/OAuth start (Server Actions, checked in `src/proxy.ts`), the
  `/api/v1` and `/api/v1/admin` proxies and the `/api/auth/*` routes. Every
  page now sets the `csrf_token` cookie when the browser has none, and the
  browser sends it on every same-origin write, Server Actions included.
- Upgrade: a browser tab opened before the upgrade has no `csrf_token`
  cookie; its first write is refused and a page reload fixes it. Scripts that
  post to the web server (not the API) must send `Origin` and the pair; API
  clients that call the API with a token are not affected.
- Client error reports are sent with a keepalive `fetch` instead of
  `navigator.sendBeacon`, which cannot carry the header.
