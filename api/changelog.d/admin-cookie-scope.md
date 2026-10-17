### Security: no console secret is readable in a cookie

- The platform console's CSRF token cookie `admin_csrf` is HttpOnly and scoped to `/api/v1/admin`, like the session cookie. The console receives the token in the body of the responses that open a session (the TOTP step, the identity-provider callback) and of `GET /api/v1/admin/auth/validate` (`csrf_token`), keeps it in memory and echoes it in `X-CSRF-Token`. No readable copy is set; the old JS-readable `admin_csrf` at `/` is cleared on sign-in and sign-out. A script on a tenant page, including one on the same host when the console is on a port of its own, cannot read the console's token.
- The console's sign-in steps echo the page's `csrf_token` before a session exists, so signing in from a fresh browser no longer fails the web proxy's CSRF check.
- **Upgrade note:** administrators signed in to the console when this ships are asked to sign in to the console again the next time they open it.
