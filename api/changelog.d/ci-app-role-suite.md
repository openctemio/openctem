### Changed: CI runs the API test suite once, as the least-privilege app role

- `Tests (Postgres + Redis)` now bootstraps the database roles, applies every migration as the migrator and runs the suite as `openctem_app`, on every pull request that changes the API as well as in the merge queue. A query that needs a grant the app role lacks now fails on the pull request instead of first in the merge queue.
- The separate `Tests (least-privilege DB role)` job, which ran the same suite a second time (6 shards), is removed: with row-level security not enabled on any table, a test that passes as the app role also passes as the owner. About 48 runner-minutes less per merge group that changes the API. Required check names are unchanged (`API CI OK`).
