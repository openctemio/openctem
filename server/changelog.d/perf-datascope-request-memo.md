### Changed: data-scope checks run their queries once per request

- A finding or asset request no longer repeats the same data-scope queries: the by-id route guard installs a per-request memo, so the scope the services resolve again, the finding or asset check they repeat, and the asset-in-scope check reuse the guard's answer. A finding sub-request by a scoped member makes 3 data-scope queries instead of 6; by an administrator of an organization with a private bug-bounty program, 3 instead of 8.
- The memo is per request only, keyed by tenant and caller; refusals and lookup errors are never reused, so access stays fail closed and a revoked role or group is seen by the next request. No migration.
