### Security: the refresh-token rotation grace needs the browser's client binding

- A rotated refresh token re-presented inside the rotation grace now gets the successor only when the request carries the same user agent **and** the browser's client binding: a random per-browser secret the web server keeps in its own HttpOnly cookie (`refresh_bind`) and forwards as `X-Refresh-Client-Binding`. A copied refresh token with a guessed user agent now ends the session as any other reuse.
- Requests without a binding (API clients posting the token in the body) get no grace.
- `/auth/token` (open or switch an organization) uses a window of at most 5 seconds; `/auth/refresh` keeps `AUTH_REFRESH_REUSE_GRACE`.
- Docs: server/docs/architecture/session-refresh.md
