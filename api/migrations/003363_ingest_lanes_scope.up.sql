-- Fair, lane-ordered, per-scope serialised claims on the ingest queue
-- (docs/rfcs/RFC-122-ingest-receipts.md, "Fairness and limits").
--
--   ingest_jobs.lane       0 urgent (a report with a KEV or critical finding
--                          from a trusted channel), 1 interactive (a person's
--                          import, a CI run whose gate waits), 2 bulk
--                          (scheduled sensor runs). Computed by the server,
--                          never taken from the report.
--   ingest_jobs.scope_key  the tenant and the asset scope a job writes (the
--                          CI run's repository, an import's uploader, a
--                          sensor report). At most one job per scope key is
--                          processing at a time (the unique partial index),
--                          so two uploads of one repository never write the
--                          same rows concurrently.
--
-- Live impact: two defaulted/nullable columns on ingest_jobs (metadata-only),
-- one partial unique index and one partial index on rows that are processing
-- or pending (small: finished rows are not in them; the build reads the table
-- once). No backfill: existing rows get lane 2 and no scope key.

ALTER TABLE ingest_jobs
    ADD COLUMN IF NOT EXISTS lane      smallint    NOT NULL DEFAULT 2,
    ADD COLUMN IF NOT EXISTS scope_key varchar(160);

ALTER TABLE ingest_jobs
    ADD CONSTRAINT chk_ingest_jobs_lane CHECK (lane BETWEEN 0 AND 2);

-- One running job per scope key: the claim relies on this to serialise a
-- scope across workers and replicas.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ingest_jobs_scope_running
    ON ingest_jobs (scope_key)
    WHERE status = 'processing' AND scope_key IS NOT NULL;

-- The claim reads due pending jobs by lane.
CREATE INDEX IF NOT EXISTS ix_ingest_jobs_pending_lane
    ON ingest_jobs (lane, available_at)
    WHERE status = 'pending';

COMMENT ON COLUMN ingest_jobs.lane IS
    '0 urgent (KEV or critical from a trusted channel), 1 interactive (a person''s import, a CI run), 2 bulk (sensor runs). Claimed in lane order, fair across tenants within a lane. Set by the server.';
COMMENT ON COLUMN ingest_jobs.scope_key IS
    'Tenant + asset scope the job writes; at most one processing job per key (ux_ingest_jobs_scope_running).';
