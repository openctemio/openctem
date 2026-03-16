-- Add tool_id column to findings table
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_id UUID REFERENCES tools(id);

-- Backfill tool_id from tool_name
UPDATE findings SET tool_id = t.id FROM tools t WHERE findings.tool_name = t.name AND findings.tool_id IS NULL;

-- Add tool_id column to pipeline_steps table
ALTER TABLE pipeline_steps ADD COLUMN IF NOT EXISTS tool_id UUID REFERENCES tools(id);

-- Backfill tool_id from tool column
UPDATE pipeline_steps SET tool_id = t.id FROM tools t WHERE pipeline_steps.tool = t.name AND pipeline_steps.tool_id IS NULL;

-- Add indexes on new columns
CREATE INDEX IF NOT EXISTS idx_findings_tool_id ON findings(tool_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_steps_tool_id ON pipeline_steps(tool_id);
