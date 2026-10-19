### Added: remediation tasks from a custom query

- `POST /api/v1/remediation/tasks/query/preview` and `POST /api/v1/remediation/tasks/query` preview and
  create a task whose findings a `findings where ...` query selects (RFC-098 §13): count, breakdowns by
  severity, asset and owner, a sample, the matches other tasks hold, the earliest SLA deadline and a
  suggested assignee. At most 1000 findings per task (`400 QUERY_TOO_MANY_MATCHES` above that).
- The query runs as the creator with their data scope, the pentest member rule and the mandatory query
  exclusions; closed and pentest findings are left out. Matches held by another active task answer
  `409 FINDINGS_IN_OTHER_TASK` unless the request skips or moves them.
- Snapshot mode (default) keeps the matches at creation; re-run (`/{task_id}/query/rerun[/preview]`) adds new
  matches on confirmation. Auto mode adds new unclaimed matches up to a cap as the creator with their current
  access, tells them in-app, can be paused, and suspends itself when the creator leaves, loses access or the
  task closes.
- `POST /api/v1/query/from-filters` turns a findings list filter into query text.
- Migration `remediation_task_queries` adds the table and the member join source `query`.
