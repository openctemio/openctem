-- Reverse of 000237: drop the v2 columns and indexes from ingest_jobs, then
-- the reports table. v2 job rows are deleted first: without their report they
-- cannot be processed, and the v1 worker must not see them.
DELETE FROM ingest_jobs WHERE protocol = 2;

DROP INDEX IF EXISTS ux_ingest_jobs_report_commit;
DROP INDEX IF EXISTS ux_ingest_jobs_report_segment;

ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS media_type;
ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS content_digest;
ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS segment_seq;
ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS ingest_report_id;
ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS protocol;

DROP INDEX IF EXISTS ix_ingest_reports_open;
DROP INDEX IF EXISTS ux_ingest_reports_tenant_sensor_report;
DROP TABLE IF EXISTS ingest_reports;
