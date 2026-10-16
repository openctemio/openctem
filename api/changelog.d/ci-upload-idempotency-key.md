### Added: `Idempotency-Key` on the CI upload endpoint

- `POST /api/v1/ci/runs/{id}/results` accepts an `Idempotency-Key` header. A retry of the same request (same key and body, same run) after a lost response gets the first answer back (`Idempotent-Replayed: true`) instead of ingesting the report again and counting another report. The key is scoped to the tenant and run, stored for one hour; the same key with another body is `422`, a key still in flight is `409` with `Retry-After`. Without Redis the header is ignored.
