### Behaviour change: a scan run's deadline is a policy cap, not a 1 h default

- A scan has no max duration unless its owner sets one. Scans that carried
  the old 1 h column default (3600 s) lose it; any other value is kept. A
  run is then bounded by the workflow's timeout or the platform's 24 h cap,
  and slow but alive work is kept going by its commands' leases.
- Every run records why its deadline is what it is (`deadline_reason`:
  `scan_max_duration`, `workflow_max_duration`, `platform_cap`, or `legacy`)
  and the run API returns it.
- A step is no longer dispatched when less time is left before the run's
  deadline than its tool needs to do anything useful: it fails
  `DEADLINE_TOO_CLOSE` and its targets join the run's unfinished targets
  (rolled over to the next scheduled run) instead of being started and
  canceled seconds later.
- Setting `timeout_seconds` to 0 on a scan update clears its max duration.
