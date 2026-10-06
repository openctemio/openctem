-- Retest commands cannot satisfy the narrower constraint; remove them first
-- (short-lived: a pending retest whose command is gone is settled unknown by
-- the retest sweep at its deadline).
DELETE FROM commands WHERE type = 'retest';
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync',
                    'update_tools', 'run_tool', 'validate', 'refresh_content',
                    'connector_sync', 'connector_scan'));
