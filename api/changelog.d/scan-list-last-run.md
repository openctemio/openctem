### Added: the scan list carries each scan's latest run and workflow name

- `GET /scans` and `GET /scans/{id}` return `last_run`: the scan's latest run with its real state (running with `progress` 0-100, completed, partial, failed, blocked with `refusal_code` and message, ...), its times and task counts. They also return `pipeline_name` for a workflow scan. Both are read in two batch queries per page, scoped to the caller's tenant.

### Behaviour change: pausing a scan turns its schedule off, not "Run now"

- A paused scan can still be run by hand (`POST /scans/{id}/trigger`). Scheduled runs, retries and automation triggers still need the scan active. A disabled scan runs for nobody. A refused trigger is recorded as a blocked run with `SCAN_NOT_TRIGGERABLE`.
