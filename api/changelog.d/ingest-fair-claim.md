### Changed: the ingest queue is fair across organizations, ordered by urgency and serialised per asset scope

- Ingest jobs (CI uploads, imports, sensor report segments) have a lane: urgent (a CI report with a critical finding or a KEV CVE, decided by the server), interactive (a person's import, a CI upload a gate waits on) and bulk (sensor reports). Urgent work is claimed first; within a lane, organizations take turns.
- At most one job per asset scope runs at a time (a CI run's repository, an organization's imports, one sensor report), enforced by a unique index, so concurrent jobs of one repository no longer write the same rows together. An organization has at most `INGEST_MAX_RUNNING_PER_TENANT` (default 2) jobs running, and within a lane the organization with fewer running jobs is served first; an organization's urgent lane goes ahead of others for one job at a time.
- Each server runs `INGEST_WORKERS` (default 4) workers; ingest writes use their own database pool, `DB_INGEST_MAX_CONNS` (default 8), apart from the API's.
- Past `INGEST_MAX_PENDING_PER_TENANT` unfinished jobs an upload gets `429` (`INGEST_QUEUE_FULL`) with a `Retry-After` from the organization's drain rate. When the queue depth cannot be read, the upload is refused with `503` (it was accepted before, for sensor segments).
- A job whose lease expires on its last attempt is dead (`apply_failed`) instead of being retried for ever; a job with no attempts left is never claimed.
- Migration `003371_ingest_lanes_scope`: `ingest_jobs.lane`, `ingest_jobs.scope_key`, two partial indexes.
- **Upgrade note:** the API opens a second database pool of `DB_INGEST_MAX_CONNS` connections; check that PostgreSQL's `max_connections` covers both pools on every server.
