### Fixed: leaked credentials without an asset can be opened and triaged by every caller who lists them

- An administrator (or a full-data role holder) from whom a private bug-bounty program asset is hidden saw leaked credentials that have no asset in `GET /api/v1/credentials`, but `GET /api/v1/credentials/{id}` and `POST /api/v1/credentials/{id}/resolve`, `/accept`, `/false-positive` answered 404 for them. The by-id reads and actions now apply the list's rule: a row with no asset is visible to every caller whose data scope is not restricted, and stays hidden from a restricted member. The same fix applies to `GET /api/v1/exposures/{id}` and its actions, which share the rule.
- Another tenant's credential, one on an asset outside the caller's scope and one on a hidden program asset still answer 404.
- `GET /api/v1/credentials/{id}` for an unknown id says "Credential not found" instead of "credential not found not found".
- Docs: none (by-id access now matches the documented data-scope rule in server/docs/architecture/authorization-matrix.md; no new behaviour)
