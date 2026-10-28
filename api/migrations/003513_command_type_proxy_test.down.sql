-- Tests are throwaway: remove them, then restore the narrower check.
DELETE FROM commands WHERE type = 'proxy_test';
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type CHECK (((type)::text = ANY ((ARRAY['scan'::character varying, 'collect'::character varying, 'health_check'::character varying, 'config_update'::character varying, 'cancel'::character varying, 'template_sync'::character varying, 'update_tools'::character varying, 'run_tool'::character varying, 'validate'::character varying, 'refresh_content'::character varying, 'connector_sync'::character varying, 'connector_scan'::character varying, 'retest'::character varying])::text[]))) NOT VALID;
ALTER TABLE commands VALIDATE CONSTRAINT chk_command_type;
