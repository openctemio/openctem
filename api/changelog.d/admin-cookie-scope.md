### Security: console cookies are no longer readable from tenant pages

- The platform console's CSRF token cookie `admin_csrf` is now HttpOnly and scoped to `/api/v1/admin`, like the session cookie. The console's pages read a copy, `admin_csrf_ui`, scoped to `/admin`; the old JS-readable `admin_csrf` at `/` is cleared on sign-in and sign-out. A script on a tenant page no longer finds the console's token in `document.cookie`.
- Residual risk until the console moves to its own origin: a script running on the tenant origin can still read console data with a live console session and, through a same-origin frame, send writes; protected writes still need a fresh authenticator code. Documented in RFC-022 (security notes).
- **Upgrade note:** administrators signed in to the console when this ships are asked to sign in to the console again the next time they open it.
