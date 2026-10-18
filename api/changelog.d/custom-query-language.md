### Added: custom query language for findings and assets

- Text queries such as `findings where state = open and asset.internet_facing = true | count by severity`
  over findings and assets: filters from the existing field allowlists, curated finding → asset
  fields, and an aggregation pipeline (count, count by, stats sum/avg/min/max/median/p90/distinct,
  time buckets, top, sort, limit). See `docs/architecture/query-language.md` (RFC-115).
- `POST /api/v1/query/explain` checks a query (errors carry the line and column), describes it in
  plain words, states the scope and rules applied and estimates its cost; `POST /api/v1/query/run`
  runs it; `GET /api/v1/query/schema?entity=` lists the fields the caller may use.
- Every query runs as the caller: tenant, data scope and the pentest campaign rule are added by the
  server, drafts, branch-only findings, bug-bounty program assets and deleted assets are left out, and
  fields that need a permission the caller lacks are unknown. Runs are read-only with a 5 second
  timeout, at most 1000 rows, a per-user rate limit and per-user and per-tenant concurrency caps.
- No migration.
