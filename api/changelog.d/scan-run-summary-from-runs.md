### Fixed: a scan's last run, run count and results come from its runs

- A scan's `last_run_id`, `last_run_at`, `last_run_status` and run counters are now recomputed from its runs after every run change (start, finish, cancel, timeout, unclaimed abort, refused trigger). Before, a refused scheduled trigger moved `last_run_at` with no run behind it and runs were counted only when they finished, so a scan could read "Last run: today" beside "Runs: 0". `total_runs` now counts running and blocked runs too.
- Migration 001157 recomputes every scan's summary once.

### Added: refused triggers are recorded as blocked runs

- A trigger refused before anything is dispatched (scope gate, freeze window, unavailable tool or sensor, no target, paused scan, platform routing, sensor policy) is recorded as a run with status `blocked`, its `refusal_code` and message, visible in the scan's run list. It is terminal and never retried. Skipped scheduled occurrences (previous run still active) stay audit entries.
- `GET /scans` and `GET /scans/{id}` return `blocked_runs`; runs return `refusal_code`.
- Migration 001157 adds `blocked` to the run status constraint, `pipeline_runs.refusal_code` and `scans.blocked_runs`.
