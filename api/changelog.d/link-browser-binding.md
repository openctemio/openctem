### Security: linking a sign-in provider is bound to the browser that started it

- `POST /api/v1/users/me/identities/{provider}/link` now returns `browser_binding`, a one-time secret for the starting browser, and `…/link/callback` refuses a completion without it (`400 OAUTH_INVALID_STATE`), the same check a social sign-in makes. The link's PKCE record is single use and expires with its state, so a replayed or expired state, or a link finished in another browser, is refused before the code exchange. The web console keeps the secret in the HttpOnly binding cookie a sign-in uses.
