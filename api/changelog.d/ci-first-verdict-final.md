### Security: a CI run's first verdict is final

- `POST /api/v1/ci/runs/{id}/evaluate` on a run that already has a verdict
  returns the stored verdict unchanged and records nothing. Before, a job could
  evaluate again (for example with `scan_failures: 0`) and overwrite a failing
  verdict, which dashboards, pipeline status and alerts read. A re-run of the
  pipeline gets its own run, as before.
