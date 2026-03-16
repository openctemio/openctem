DROP INDEX IF EXISTS idx_pipeline_steps_tool_id;
DROP INDEX IF EXISTS idx_findings_tool_id;
ALTER TABLE pipeline_steps DROP COLUMN IF EXISTS tool_id;
ALTER TABLE findings DROP COLUMN IF EXISTS tool_id;
