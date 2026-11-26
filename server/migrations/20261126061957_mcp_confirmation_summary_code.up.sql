-- The summary of a pending MCP write action as a stable message code plus
-- typed values (docs/architecture/mcp-authorization.md), so the web shows it
-- in the reader's language and shows the AI-written comment and its client
-- visibility as separate fields. summary keeps the English text.
--
-- Nullable adds without a default (metadata only); the checks are added
-- NOT VALID and validated afterwards. Rows live five minutes.

ALTER TABLE mcp_action_confirmations ADD COLUMN IF NOT EXISTS summary_code varchar(96);
ALTER TABLE mcp_action_confirmations ADD COLUMN IF NOT EXISTS summary_params jsonb;

ALTER TABLE mcp_action_confirmations DROP CONSTRAINT IF EXISTS chk_mcp_action_confirmations_summary_code;
ALTER TABLE mcp_action_confirmations ADD CONSTRAINT chk_mcp_action_confirmations_summary_code
    CHECK (summary_code IS NULL OR summary_code ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$') NOT VALID;
ALTER TABLE mcp_action_confirmations VALIDATE CONSTRAINT chk_mcp_action_confirmations_summary_code;

ALTER TABLE mcp_action_confirmations DROP CONSTRAINT IF EXISTS chk_mcp_action_confirmations_summary_params;
ALTER TABLE mcp_action_confirmations ADD CONSTRAINT chk_mcp_action_confirmations_summary_params
    CHECK (summary_params IS NULL OR (jsonb_typeof(summary_params) = 'object' AND pg_column_size(summary_params) <= 16384)) NOT VALID;
ALTER TABLE mcp_action_confirmations VALIDATE CONSTRAINT chk_mcp_action_confirmations_summary_params;

COMMENT ON COLUMN mcp_action_confirmations.summary_code IS
    'Stable code of the summary (for example mcp.add_finding_comment); NULL on older rows, where summary is shown.';
COMMENT ON COLUMN mcp_action_confirmations.summary_params IS
    'Typed values of summary_code (finding, severity, content, client_visible). Display text only.';
