### Fixed: a task every sensor withholds says why instead of waiting in silence

- When a sensor's grant, local policy or the scan's intensity keeps a queued task from it, the reason is recorded on the task (its code only, at most every 10 minutes) and logged once per sensor and reason per 10 minutes. Neither the record nor the log carries targets, settings or the sensor's identity on the task.
- "Why waiting?" on a run's task names that reason, also for platform scanning and the shared fleet (`withheld` on `GET /scan-runs/{id}/tasks/{task_id}/placement`).
- A run that no sensor picked up ends with the reason in its message, e.g. "withheld by sensor permissions: credentials", and its tasks show it, translated (`withheld_reason` on run tasks).
