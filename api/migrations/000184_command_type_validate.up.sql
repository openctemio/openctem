-- RFC-010 Validation Engine: allow the `validate` command type so a finding
-- validation (safe-check) job can be enqueued as a platform/tenant command.
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync', 'update_tools', 'run_tool', 'validate'));
