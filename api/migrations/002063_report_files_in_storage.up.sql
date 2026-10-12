-- Report templates and stored report files move from Postgres bytea to the
-- organization's file storage (RFC-084). This migration is the expand step:
-- new files go to the storage (storage_key/storage_provider) and content
-- stays NULL; the rows already holding bytes keep them until the API's
-- report-file-migration job copies each to the storage (checked against its
-- SHA-256) and clears content. A later release drops content.
--
-- Deleting a row whose file is in the storage (directly or by a cascade from
-- its report, campaign or organization) queues the file in
-- storage_blob_deletions; the attachment-retention job deletes it from the
-- organization's storage. A row deleted because its organization is being
-- deleted queues nothing: organization erasure removes the whole namespace.

ALTER TABLE pentest_report_templates
    ADD COLUMN IF NOT EXISTS storage_key VARCHAR(500),
    ADD COLUMN IF NOT EXISTS storage_provider VARCHAR(20),
    ADD COLUMN IF NOT EXISTS size_bytes BIGINT;
UPDATE pentest_report_templates SET size_bytes = octet_length(content) WHERE size_bytes IS NULL;
ALTER TABLE pentest_report_templates ALTER COLUMN content DROP NOT NULL;
ALTER TABLE pentest_report_templates DROP CONSTRAINT IF EXISTS chk_pentest_report_templates_size;
ALTER TABLE pentest_report_templates ADD CONSTRAINT chk_pentest_report_templates_size
    CHECK (content IS NULL OR octet_length(content) BETWEEN 1 AND 10485760);
ALTER TABLE pentest_report_templates DROP CONSTRAINT IF EXISTS chk_pentest_report_templates_stored;
ALTER TABLE pentest_report_templates ADD CONSTRAINT chk_pentest_report_templates_stored
    CHECK (content IS NOT NULL OR (storage_key IS NOT NULL AND storage_provider IS NOT NULL));

ALTER TABLE pentest_report_files
    ADD COLUMN IF NOT EXISTS storage_key VARCHAR(500),
    ADD COLUMN IF NOT EXISTS storage_provider VARCHAR(20),
    ADD COLUMN IF NOT EXISTS size_bytes BIGINT;
UPDATE pentest_report_files SET size_bytes = octet_length(content) WHERE size_bytes IS NULL;
ALTER TABLE pentest_report_files ALTER COLUMN content DROP NOT NULL;
ALTER TABLE pentest_report_files DROP CONSTRAINT IF EXISTS chk_pentest_report_files_size;
ALTER TABLE pentest_report_files ADD CONSTRAINT chk_pentest_report_files_size
    CHECK (content IS NULL OR octet_length(content) BETWEEN 1 AND 52428800);
ALTER TABLE pentest_report_files DROP CONSTRAINT IF EXISTS chk_pentest_report_files_stored;
ALTER TABLE pentest_report_files ADD CONSTRAINT chk_pentest_report_files_stored
    CHECK (content IS NOT NULL OR (storage_key IS NOT NULL AND storage_provider IS NOT NULL));

CREATE TABLE IF NOT EXISTS storage_blob_deletions (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    storage_provider VARCHAR(20) NOT NULL,
    storage_key      VARCHAR(500) NOT NULL,
    source           VARCHAR(40) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_storage_blob_deletions_tenant ON storage_blob_deletions (tenant_id);

COMMENT ON TABLE storage_blob_deletions IS
    'Files in the file storage whose row was deleted; the attachment-retention job deletes them (RFC-084)';

CREATE OR REPLACE FUNCTION queue_storage_blob_deletion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Skipped while the organization itself is deleted (its row is already
    -- gone when the cascade reaches this table).
    IF OLD.storage_key IS NOT NULL AND EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        INSERT INTO storage_blob_deletions (tenant_id, storage_provider, storage_key, source)
        VALUES (OLD.tenant_id, OLD.storage_provider, OLD.storage_key, TG_TABLE_NAME);
    END IF;
    RETURN OLD;
END;
$$;

COMMENT ON FUNCTION queue_storage_blob_deletion() IS
    'AFTER DELETE trigger: queues the deleted row''s stored file (tenant_id, storage_provider, storage_key) for deletion from the file storage';

DROP TRIGGER IF EXISTS trg_pentest_report_templates_blob ON pentest_report_templates;
CREATE TRIGGER trg_pentest_report_templates_blob
    AFTER DELETE ON pentest_report_templates
    FOR EACH ROW EXECUTE FUNCTION queue_storage_blob_deletion();

DROP TRIGGER IF EXISTS trg_pentest_report_files_blob ON pentest_report_files;
CREATE TRIGGER trg_pentest_report_files_blob
    AFTER DELETE ON pentest_report_files
    FOR EACH ROW EXECUTE FUNCTION queue_storage_blob_deletion();

COMMENT ON TABLE pentest_report_templates IS
    'Organization Word templates for pentest reports (RFC-076); the file is in the file storage (storage_key), or in content until moved';
COMMENT ON TABLE pentest_report_files IS
    'Stored pentest report artifacts: download returns these bytes, from the file storage (storage_key) or from content until moved';
