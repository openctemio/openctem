### Security: in production the console needs a CSRF secret shared by every replica

- The console's CSRF tokens are signed with a key derived from the session
  secret (`AUTH_JWT_SECRET`, or `APP_ENCRYPTION_KEY` when it is derived). In
  production the API now refuses to start without one, instead of drawing a
  per-process random key that breaks the token on the next replica. With
  `AUTH_PROVIDER=oidc` set `AUTH_JWT_SECRET` explicitly.
