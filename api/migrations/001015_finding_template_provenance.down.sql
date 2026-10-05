ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS chk_findings_template_provenance,
    DROP COLUMN IF EXISTS template_seen_at,
    DROP COLUMN IF EXISTS templates_digest,
    DROP COLUMN IF EXISTS templates_version,
    DROP COLUMN IF EXISTS template_path,
    DROP COLUMN IF EXISTS template_digest;
