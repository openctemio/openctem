-- A command type for the Test button of a proxy pool: one sensor tests each
-- endpoint of a pool (the platform never connects to a
-- proxy itself). Adds 'proxy_test' to the types a command may have.
--
-- NOT VALID then VALIDATE keeps the lock on the commands table short: the
-- new check only widens the old one, so existing rows always satisfy it.
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type CHECK (((type)::text = ANY ((ARRAY['scan'::character varying, 'collect'::character varying, 'health_check'::character varying, 'config_update'::character varying, 'cancel'::character varying, 'template_sync'::character varying, 'update_tools'::character varying, 'run_tool'::character varying, 'validate'::character varying, 'refresh_content'::character varying, 'connector_sync'::character varying, 'connector_scan'::character varying, 'retest'::character varying, 'proxy_test'::character varying])::text[]))) NOT VALID;
ALTER TABLE commands VALIDATE CONSTRAINT chk_command_type;
