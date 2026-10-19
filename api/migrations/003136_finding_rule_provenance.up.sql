-- Which rules found a finding (docs/architecture/rule-sources.md): the
-- platform's or the organization's, and for the organization's, which of
-- its scanner templates at which version. Recorded with the template
-- provenance of each sighting. Nullable columns, no default: no rewrite of
-- findings; the CHECK is NOT VALID (every existing row is NULL).

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS rule_source VARCHAR(16),
    ADD COLUMN IF NOT EXISTS custom_template_id UUID,
    ADD COLUMN IF NOT EXISTS custom_template_version VARCHAR(50);

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_rule_source;
ALTER TABLE findings
    ADD CONSTRAINT chk_findings_rule_source
    CHECK (rule_source IS NULL OR rule_source IN ('platform', 'tenant')) NOT VALID;

COMMENT ON COLUMN findings.rule_source IS 'Rules of the last sighting: platform or tenant (the organization''s own)';
COMMENT ON COLUMN findings.custom_template_id IS 'The organization''s scanner template of the last sighting (scanner_templates.id, same tenant; no FK: the template may be deleted)';
COMMENT ON COLUMN findings.custom_template_version IS 'That template''s version at the sighting';
