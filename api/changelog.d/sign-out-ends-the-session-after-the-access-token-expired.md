### Security: signing out ends the session after the access token expired

- `POST /auth/logout` accepts the refresh token (in the body, or in the
  refresh cookie with the CSRF pair) and ends that session. It used to need
  the 15-minute access token. The web sent only that token, and skipped the
  call once the cookie had expired. A user who idled and then signed out
  cleared their browser cookies, but the server session and its refresh
  chain stayed valid for up to 7 days (30 with rotation).
- The web sign-out sends the refresh token. A request without one still
  signs out by the access token.
