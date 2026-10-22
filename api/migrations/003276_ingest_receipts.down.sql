-- Reverts 003276_ingest_receipts: drops the action log and the daily fact,
-- removes the run receipts and turns the upload receipts back into
-- finding_imports rows.

DROP TABLE IF EXISTS dash_ingest_day;
DROP TABLE IF EXISTS finding_ingest_actions;
DROP TABLE IF EXISTS ingest_receipt_coverage;

-- Run receipts have no file and no place in finding_imports.
DELETE FROM ingest_receipts WHERE source_kind <> 'upload';
-- An upload receipt of the new API spans every file of the upload; the old
-- table needs a format and a name hash.
UPDATE ingest_receipts SET format = 'unknown' WHERE format IS NULL;
UPDATE ingest_receipts SET filename_sha256 = repeat('0', 64) WHERE filename_sha256 IS NULL;

DROP INDEX IF EXISTS idx_ingest_receipts_retention;
ALTER TABLE ingest_receipts
    DROP CONSTRAINT IF EXISTS ux_ingest_receipts_source,
    DROP CONSTRAINT IF EXISTS chk_ingest_receipts_errors,
    DROP CONSTRAINT IF EXISTS chk_ingest_receipts_counts,
    DROP CONSTRAINT IF EXISTS chk_ingest_receipts_status,
    DROP CONSTRAINT IF EXISTS chk_ingest_receipts_coverage,
    DROP CONSTRAINT IF EXISTS chk_ingest_receipts_source_kind;

ALTER TABLE ingest_receipts
    DROP COLUMN IF EXISTS finished_at,
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS errors,
    DROP COLUMN IF EXISTS actions_truncated,
    DROP COLUMN IF EXISTS actions_recorded,
    DROP COLUMN IF EXISTS findings_suppressed,
    DROP COLUMN IF EXISTS findings_failed,
    DROP COLUMN IF EXISTS findings_untouched,
    DROP COLUMN IF EXISTS findings_closed,
    DROP COLUMN IF EXISTS findings_reopened,
    DROP COLUMN IF EXISTS findings_received,
    DROP COLUMN IF EXISTS reports,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS coverage_note,
    DROP COLUMN IF EXISTS coverage,
    DROP COLUMN IF EXISTS tool_name,
    DROP COLUMN IF EXISTS source_ref,
    DROP COLUMN IF EXISTS source_kind;

ALTER TABLE ingest_receipts ALTER COLUMN filename_sha256 SET NOT NULL;
ALTER TABLE ingest_receipts ALTER COLUMN format SET NOT NULL;

ALTER TABLE ingest_receipts RENAME CONSTRAINT chk_ingest_receipts_sha TO chk_finding_imports_sha;
ALTER TABLE ingest_receipts RENAME CONSTRAINT chk_ingest_receipts_upload_counts TO chk_finding_imports_counts;
ALTER TABLE ingest_receipts RENAME CONSTRAINT ingest_receipts_tenant_id_fkey TO finding_imports_tenant_id_fkey;
ALTER TABLE ingest_receipts RENAME CONSTRAINT ingest_receipts_actor_user_id_fkey TO finding_imports_actor_user_id_fkey;
ALTER INDEX idx_ingest_receipts_tenant_created RENAME TO idx_finding_imports_tenant_created;
ALTER INDEX ingest_receipts_pkey RENAME TO finding_imports_pkey;
ALTER TABLE ingest_receipts RENAME TO finding_imports;

COMMENT ON TABLE finding_imports IS 'One row per file a person imported (POST /findings/import, never a preview): the producer of the findings whose scan_id and the assets whose import_id is this id.';
COMMENT ON COLUMN finding_imports.filename_sha256 IS 'SHA-256 of the uploaded file name; the name itself is kept only in the audit log.';
