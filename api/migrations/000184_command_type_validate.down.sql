-- Revert: drop `validate` from the allowed command types. Any existing
-- `validate` rows must be removed first or this ALTER will fail (intended: the
-- down migration should not run while validation jobs exist).
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync', 'update_tools', 'run_tool'));
