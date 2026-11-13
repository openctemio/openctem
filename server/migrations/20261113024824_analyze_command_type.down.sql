-- Back to the checks before analysis jobs. Rows the old checks cannot hold
-- are removed first: 'analyze' commands, and worker runs that never reached
-- a worker (no sensor: queued, canceled, refused or failed).
ALTER TABLE ai_runs DROP CONSTRAINT IF EXISTS chk_ai_runs_result_digest;
ALTER TABLE ai_runs DROP COLUMN IF EXISTS result_digest;

DELETE FROM ai_runs WHERE executor IN ('platform_worker', 'tenant_worker') AND sensor_id IS NULL;
ALTER TABLE ai_runs DROP CONSTRAINT IF EXISTS chk_ai_runs_worker;
ALTER TABLE ai_runs ADD CONSTRAINT chk_ai_runs_worker CHECK ((executor IN ('platform_worker', 'tenant_worker')) = (sensor_id IS NOT NULL)) NOT VALID;
ALTER TABLE ai_runs VALIDATE CONSTRAINT chk_ai_runs_worker;

DELETE FROM commands WHERE type = 'analyze';
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type CHECK (((type)::text = ANY ((ARRAY['scan'::character varying, 'collect'::character varying, 'health_check'::character varying, 'config_update'::character varying, 'cancel'::character varying, 'template_sync'::character varying, 'update_tools'::character varying, 'run_tool'::character varying, 'validate'::character varying, 'refresh_content'::character varying, 'connector_sync'::character varying, 'connector_scan'::character varying, 'retest'::character varying, 'proxy_test'::character varying])::text[]))) NOT VALID;
ALTER TABLE commands VALIDATE CONSTRAINT chk_command_type;
