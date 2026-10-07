### Fixed: pages knew who you were only until a reload; the member list refused status=all

- The members page, Account › Activity, the pentest campaign list and the
  pentest campaign and finding sheets read the signed-in user from the auth
  store, which is empty after a reload (the session lives in an httpOnly
  cookie). They treated you as someone else: your own activity did not load,
  "is it me" checks failed, and the pentest member picker listed nobody. They
  now use the profile API (`useDisplayUser`), and a test fails on any new
  reader of the store's user outside the shared hooks.
- `GET /api/v1/tenants/{tenant}/members?include=user&status=all` (and
  `status=offboarded`) answered 400 "unknown member status filter": the
  handler and the repository accepted them, the service did not. They agree
  now.
