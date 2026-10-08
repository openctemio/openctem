### Added: every retest is a scan run

- A scan run now has a `kind` (`scan`, `quick`, `retest`, `validation`, `test`,
  `connector`, `system`) and a `subject`. A run that executes no scan workflow
  (a retest) has no `scan_workflow_id`. Migration `001301`.
- Requesting a retest records a run of kind `retest` with one step. Both of the
  retest's sensor commands are tasks of that run, so their status and logs are
  read from the run page. The run ends when the retest reaches its verdict.
  `finding_retests.run_id` links the retest to its run, and the retest API
  returns it as `run_id`.
- `GET /api/v1/scan-runs` takes `kind` (comma-separated) and `include_system`.
  System runs are hidden unless one of these asks for them. Each run in the
  response carries `kind` and `subject`.

### Security: a retest run follows the access rules of its finding

- A run about a finding exposes the finding's target and the check output. To
  read it, its tasks, its stages or its logs, the caller needs `findings:read`
  and the finding inside their data scope. Otherwise the answer is 404. The
  Runs list leaves these runs out for callers without `findings:read` or with a
  restricted data scope.
