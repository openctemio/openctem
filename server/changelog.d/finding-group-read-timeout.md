### Security: the grouped findings view and the components list stop after 5 seconds

- `GET /api/v1/findings/groups` (every `group_by`), `GET /api/v1/findings/related-cves/{cveId}` and the components list, facets and summary (`GET /api/v1/components`, `GET /api/v1/components/summary`) ran on the shared database pool with no statement timeout of their own, so a broad grouping on a large organization could hold a connection for as long as the database role allowed (or without limit on an install without the least-privilege roles). They now run in a read-only transaction with a 5 s statement timeout, like the findings list.
- A read that runs out of time answers `503 QUERY_TIMEOUT` ("narrow the search or the filters") instead of a 500, is counted in the new metric `openctem_db_read_timeouts_total{read}` and is logged once by name, never with its values.
- Every interactive list, count, stats, facet and group read now opens its transaction through one helper, so the bound cannot be forgotten on a new read.
- **Upgrade note:** on a very large organization an unfiltered grouping can now answer `QUERY_TIMEOUT`; narrow the filter (severity, status, a search).
- Docs: server/docs/architecture/list-query-contract.md
