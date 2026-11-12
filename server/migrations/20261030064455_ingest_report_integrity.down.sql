ALTER TABLE ingest_reports DROP CONSTRAINT IF EXISTS chk_ingest_reports_integrity;
ALTER TABLE ingest_reports
    DROP COLUMN IF EXISTS content_sha256,
    DROP COLUMN IF EXISTS integrity;
