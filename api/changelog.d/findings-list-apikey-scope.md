### Security: API keys never get full-data access on the findings list

- `GET /api/v1/findings` (and the stats, groups, related CVEs and export paths that share its filter) no longer gives an `oct_` API key its holder's full-data role. A key held by a user with a full-data role (for example an auditor or program lead role) now lists only the findings in the user's data scope, as every other data-scope path already did. Full data through a key needs an explicit full-data key, which does not exist yet.
- A request caller with no acting user now reads no scoped findings (fail closed) instead of an unrestricted list. No route reaches this today.
