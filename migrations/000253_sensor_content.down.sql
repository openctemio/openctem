-- Revert 000253. refresh_content commands must be gone before the constraint
-- can narrow again.
DROP INDEX IF EXISTS idx_commands_open_refresh_content;
DELETE FROM commands WHERE type = 'refresh_content';
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync', 'update_tools', 'run_tool', 'validate'));
DROP TABLE IF EXISTS sensor_content_policies;
