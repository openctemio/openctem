-- Connector commands cannot satisfy the narrower constraint; remove them
-- first (they are short-lived sync and scan requests, re-queued by the
-- integration schedule after an upgrade).
DELETE FROM commands WHERE type IN ('connector_sync', 'connector_scan');
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync', 'update_tools', 'run_tool', 'validate', 'refresh_content'));
