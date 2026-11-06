ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_rule_source;
ALTER TABLE findings
    DROP COLUMN IF EXISTS custom_template_version,
    DROP COLUMN IF EXISTS custom_template_id,
    DROP COLUMN IF EXISTS rule_source;
