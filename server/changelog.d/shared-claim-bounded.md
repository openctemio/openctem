### Changed: a shared sensor's poll no longer ranks every pending shared job

- The shared poll now reads, per organization with pending shared work, only its first round of jobs
  straight from a new index, and counts in-flight shared jobs through an index that holds no finished job.
  Its work is bounded by the organizations with pending shared work (at most 200 ranked per poll), not by
  the depth of their queues or by shared job history. The order of offered jobs is unchanged: rounds of five
  per organization, fewest in flight first, one verification job may jump (RFC-129).
- Migrations `003447_commands_shared_inflight_index` and `003448_commands_shared_pending_index` build two
  partial indexes on `commands` with `CREATE INDEX CONCURRENTLY` (no write lock; build time grows with the
  number of pending and in-flight shared jobs, which is small).
