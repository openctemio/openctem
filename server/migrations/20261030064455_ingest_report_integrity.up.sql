-- How a committed sensor report proved it is complete (RFC-026 §3.5a), and
-- the hash that identifies its content.
--   single       one segment: the one digest covers the whole report
--   manifest     segmented, and the commit's manifest (per-segment content
--                hash, size, totals, report hash) matched what was stored
--   digest_only  segmented, committed with segment digests only (older SDKs);
--                never proof for coverage auto-close
-- NULL while the report is uncommitted. Existing committed rows are
-- classified from their segment count (a metadata-only column plus a small
-- backfill: one row per report).
ALTER TABLE ingest_reports
    ADD COLUMN IF NOT EXISTS integrity TEXT,
    ADD COLUMN IF NOT EXISTS content_sha256 BYTEA;

ALTER TABLE ingest_reports DROP CONSTRAINT IF EXISTS chk_ingest_reports_integrity;
ALTER TABLE ingest_reports ADD CONSTRAINT chk_ingest_reports_integrity
    CHECK (integrity IS NULL OR integrity IN ('single', 'manifest', 'digest_only')) NOT VALID;
ALTER TABLE ingest_reports VALIDATE CONSTRAINT chk_ingest_reports_integrity;

UPDATE ingest_reports
SET integrity = CASE WHEN implicit_commit OR segment_count = 1 THEN 'single' ELSE 'digest_only' END
WHERE committed_at IS NOT NULL AND integrity IS NULL;

COMMENT ON COLUMN ingest_reports.integrity IS
    'How the committed report proved completeness: single, manifest or digest_only (never proof for coverage auto-close); NULL while uncommitted.';
COMMENT ON COLUMN ingest_reports.content_sha256 IS
    'SHA-256 over the decoded SHA-256 of every segment, in segment order: one hash for the report content.';
