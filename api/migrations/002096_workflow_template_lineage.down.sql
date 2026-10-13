DROP INDEX IF EXISTS idx_scan_workflows_source_template;
ALTER TABLE scan_workflows
    DROP COLUMN IF EXISTS source_spec,
    DROP COLUMN IF EXISTS source_template_id;
