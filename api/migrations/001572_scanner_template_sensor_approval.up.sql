-- Custom template versions approved for sensors (RFC-040 §5.8 and §11.5): a
-- template version reaches a sensor only once people approved it like a scope
-- widening and the job signer recorded its digest in its ledger.
ALTER TABLE scanner_templates
    ADD COLUMN IF NOT EXISTS ledger_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS sensor_approvals JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS content_author_id UUID;

ALTER TABLE scanner_templates DROP CONSTRAINT IF EXISTS chk_scanner_template_ledger_sha256;
ALTER TABLE scanner_templates ADD CONSTRAINT chk_scanner_template_ledger_sha256
    CHECK (ledger_sha256 IS NULL OR ledger_sha256 ~ '^sha256:[0-9a-f]{64}$');

COMMENT ON COLUMN scanner_templates.ledger_sha256 IS
    'Digest (sha256:<hex>) of the approved version the job signer''s ledger holds; the template is approved for sensors while it equals sha256:content_hash.';
COMMENT ON COLUMN scanner_templates.sensor_approvals IS
    'Approvals of template versions for sensors: [{user_id, approved_at, sha256}]; only those of the current version count.';
COMMENT ON COLUMN scanner_templates.content_author_id IS
    'Who wrote the current version (the requester, who cannot approve it); NULL for a synced version.';

-- Templates in use before this release keep working: their current version
-- counts as approved. The operator reviews them in the ledger bootstrap
-- (server -signer-ledger-export).
UPDATE scanner_templates
SET ledger_sha256 = 'sha256:' || content_hash,
    content_author_id = created_by
WHERE status = 'active' AND ledger_sha256 IS NULL AND content_hash ~ '^[0-9a-f]{64}$';
