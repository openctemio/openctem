-- Down: refused while any file lives only in the file storage (its bytes are
-- not in the database). Run with the API stopped after copying them back, or
-- delete those rows first.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pentest_report_templates WHERE content IS NULL)
       OR EXISTS (SELECT 1 FROM pentest_report_files WHERE content IS NULL) THEN
        RAISE EXCEPTION 'report files live in the file storage: they cannot go back into the database by migration';
    END IF;
END $$;

DROP TRIGGER IF EXISTS trg_pentest_report_files_blob ON pentest_report_files;
DROP TRIGGER IF EXISTS trg_pentest_report_templates_blob ON pentest_report_templates;
DROP FUNCTION IF EXISTS queue_storage_blob_deletion();
DROP TABLE IF EXISTS storage_blob_deletions;

ALTER TABLE pentest_report_files DROP CONSTRAINT IF EXISTS chk_pentest_report_files_stored;
ALTER TABLE pentest_report_files DROP CONSTRAINT IF EXISTS chk_pentest_report_files_size;
ALTER TABLE pentest_report_files ADD CONSTRAINT chk_pentest_report_files_size
    CHECK (octet_length(content) BETWEEN 1 AND 52428800);
ALTER TABLE pentest_report_files ALTER COLUMN content SET NOT NULL;
ALTER TABLE pentest_report_files
    DROP COLUMN IF EXISTS size_bytes,
    DROP COLUMN IF EXISTS storage_provider,
    DROP COLUMN IF EXISTS storage_key;

ALTER TABLE pentest_report_templates DROP CONSTRAINT IF EXISTS chk_pentest_report_templates_stored;
ALTER TABLE pentest_report_templates DROP CONSTRAINT IF EXISTS chk_pentest_report_templates_size;
ALTER TABLE pentest_report_templates ADD CONSTRAINT chk_pentest_report_templates_size
    CHECK (octet_length(content) BETWEEN 1 AND 10485760);
ALTER TABLE pentest_report_templates ALTER COLUMN content SET NOT NULL;
ALTER TABLE pentest_report_templates
    DROP COLUMN IF EXISTS size_bytes,
    DROP COLUMN IF EXISTS storage_provider,
    DROP COLUMN IF EXISTS storage_key;

COMMENT ON TABLE pentest_report_templates IS 'Organization Word templates for pentest reports (RFC-076); the file is kept in content';
COMMENT ON TABLE pentest_report_files IS 'Stored pentest report artifacts: download returns these bytes';
