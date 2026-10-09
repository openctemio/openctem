ALTER TABLE scanner_templates DROP CONSTRAINT IF EXISTS chk_scanner_template_ledger_sha256;
ALTER TABLE scanner_templates
    DROP COLUMN IF EXISTS content_author_id,
    DROP COLUMN IF EXISTS sensor_approvals,
    DROP COLUMN IF EXISTS ledger_sha256;
