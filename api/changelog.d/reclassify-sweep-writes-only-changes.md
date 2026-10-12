### Changed: the priority reclassification sweep writes only what changed

- The whole-tenant sweep, which runs on a schedule and after KEV/EPSS
  refreshes, rewrote every finding it re-examined. It now persists a finding
  only when its priority class, reason, reachability or SLA changed. In a
  10-minute window on a tenant with 525k findings, it rewrote 2,189 of 34.7k
  re-examined findings (before: all 20.9k), and it went through findings 1.65
  times faster.
- A re-confirmed class no longer adds a `priority_class_audit_log` row. The
  log records transitions, as the ingest path already did. Before, every
  sweep added one row per open finding (20.8k rows in 10 minutes).
- The sweep reads the distinct assets of the tenant's open findings in one
  query instead of paging every open finding with a count per page.
