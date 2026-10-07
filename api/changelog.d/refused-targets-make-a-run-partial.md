### Changed: a task whose sensor skipped some targets ends the run partial

- A sensor with sdk-go #191 removes a scan target that its local policy refuses or cannot check, such as a name that does not resolve or a wildcard pattern. It runs the task on the other targets and completes it with `refused_targets` in its result metadata.
- The platform reads that list, bounded and cleaned. The step ends `partial` (code `TARGETS_SKIPPED`), and so does the run, instead of "completed". Before the sensor change, one unresolvable target failed the whole task.
- A batched step sums the skipped targets of its completed batches.
- Run tasks (`GET /api/v1/pipeline-runs/{id}` and `/tasks`) carry `skipped_targets` (at most 20) and `skipped_targets_total`. The run page shows "Completed with N targets skipped: api.example.com (does not resolve)" under the task status.
- Skipped targets do not roll over to the next scheduled run.
