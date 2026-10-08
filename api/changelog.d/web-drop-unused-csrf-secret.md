### Removed: the unused web `CSRF_SECRET`

- The web console never used `CSRF_SECRET`: CSRF protection is the
  double-submit cookie (a random `csrf_token` cookie echoed in the
  `X-CSRF-Token` header, checked by the API and the web auth routes), which
  needs no secret. The Compose file no longer requires it, the console no
  longer warns about it, and it is gone from the env examples and docs.
  Delete it from your environment; leaving it set has no effect.
