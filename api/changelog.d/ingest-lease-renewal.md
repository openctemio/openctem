### Fixed: a long import completes, and a queued upload is re-checked when it is applied

- The ingest worker renews a running job's five-minute lease, so an import that takes longer than the lease succeeds instead of being cancelled on every attempt. `INGEST_MAX_JOB_DURATION` (default `30m`) is the hard cap on one job. Completing or failing a job now only writes for the attempt the worker claimed: a worker that lost its lease stops and writes nothing.
- Security: a queued file import is checked again when it is applied. An upload sent with an API key that was revoked, expired or deleted meanwhile fails with `uploader_not_permitted`, and `findings:approve` (which lets a VEX statement request a false positive) is kept only while the uploader or the key still holds it. Rights are never widened.
- An unkeyed upload whose duplicate lookup fails answers `503` (not `500`). `GET /findings/imports/{id}/result` no longer answers `applied` for an upload that has no job unless its receipt finished; otherwise it answers `404`.
- A retried CI tool export gives back the report slots its failed attempt took, so a run's report cap is not used twice.
