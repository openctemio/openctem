-- RFC-039 tool retest: a finding is re-checked by the retest handler of the
-- tool that produced it, through one command of type retest (sdk-go tool
-- contract). Without the type the CHECK refuses every such command.
--
-- NOT VALID then VALIDATE: the new constraint only widens the set, so the
-- validation scan finds nothing, and adding it NOT VALID first avoids holding
-- the ACCESS EXCLUSIVE lock for that scan on a populated commands table.
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync',
                    'update_tools', 'run_tool', 'validate', 'refresh_content',
                    'connector_sync', 'connector_scan', 'retest')) NOT VALID;
ALTER TABLE commands VALIDATE CONSTRAINT chk_command_type;
