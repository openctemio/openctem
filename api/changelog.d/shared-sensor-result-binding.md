### Security: a shared sensor's results are bound to the job it holds, in the job's organization

- Protocol v2 accepts results from a shared sensor (scope `instance`) only on the command-bound routes, for a shared job it holds, under the lease epoch it states in `X-OpenCTEM-Lease-Epoch`. They are stored in the organization of the command, never one named by the request; anything else answers `command-not-found` and stores nothing (RFC-100 §8).
- A shared sensor never pushes: every results route that names no command answers 403 `scope-denied`, the ingest service refuses its unbound reports, and the database refuses such a report row.
- An organization sensor can no longer post results for a shared job, even one of its own organization.
- The ingest worker drops a queued report of a shared sensor that no longer holds the job (audited), as it already did for a revoked or disabled sensor.
- `ingest_reports` replaces its composite (tenant, sensor) foreign key with a key on `sensor_id` and the trigger `trigger_ingest_reports_sensor_binding`, which keeps an organization sensor's reports in its organization and a shared sensor's report on a held shared job of the report's organization (migrations `002714_ingest_reports_shared_sensor`, `002715_ingest_reports_shared_sensor_validate`).
- **Upgrade note:** no downtime needed; the constraint is added `NOT VALID` and validated in its own migration. The downgrade removes shared sensors' reports.
