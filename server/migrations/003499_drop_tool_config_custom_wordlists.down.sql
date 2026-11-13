ALTER TABLE tenant_tool_configs ADD COLUMN IF NOT EXISTS custom_wordlists jsonb DEFAULT '[]'::jsonb;
