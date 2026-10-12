### Changed: groups, assignment rules, scope rules and AI triage history page with `page` and `per_page`

- These lists now read `page` and `per_page` through the shared parser,
  instead of `limit` and `offset`. Their responses report `page` and
  `per_page` instead of `limit` and `offset`:
  - `GET /api/v1/groups`, `/groups/{id}/members` and `/groups/{id}/assets`;
  - `GET /api/v1/assignment-rules`;
  - `GET /api/v1/groups/{id}/scope-rules`;
  - `GET /api/v1/findings/{id}/ai-triage/history`.
- A bad value is answered 400 instead of falling back silently. `per_page` is
  capped at 100.
- **Behaviour change:** clients sending `limit`/`offset` to these endpoints get
  the first page until they send `page`/`per_page`. The console is updated.
