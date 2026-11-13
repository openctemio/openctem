-- Analysis jobs for AI workers (docs/rfcs/RFC-131-ai-analysis.md §5): an AI
-- worker is a sensor on the ai-worker grant profile that claims 'analyze'
-- commands from the command queue, as a scanner claims scans.
--
-- 1. 'analyze' joins the types a command may have.
-- 2. chk_ai_runs_worker: a run on a worker gets its sensor when a worker
--    claims the job, so a worker run without a sensor is valid while it is
--    queued and when it ended without reaching a worker (canceled, refused,
--    failed). Running, waiting and completed worker runs still need one; a
--    built-in or external run still never has one. Before, a worker run
--    needed a sensor from the start, which a queued job cannot name.
-- 3. ai_runs.result_digest: the sha256 of the result a worker returned.
--
-- Live impact: no data changes. Both checks only widen the old ones, so every
-- existing row satisfies them; NOT VALID then VALIDATE keeps the locks short
-- (VALIDATE scans without blocking writes). The new column is nullable with
-- no default (no table rewrite).

ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type CHECK (((type)::text = ANY ((ARRAY['scan'::character varying, 'collect'::character varying, 'health_check'::character varying, 'config_update'::character varying, 'cancel'::character varying, 'template_sync'::character varying, 'update_tools'::character varying, 'run_tool'::character varying, 'validate'::character varying, 'refresh_content'::character varying, 'connector_sync'::character varying, 'connector_scan'::character varying, 'retest'::character varying, 'proxy_test'::character varying, 'analyze'::character varying])::text[]))) NOT VALID;
ALTER TABLE commands VALIDATE CONSTRAINT chk_command_type;

ALTER TABLE ai_runs DROP CONSTRAINT IF EXISTS chk_ai_runs_worker;
ALTER TABLE ai_runs ADD CONSTRAINT chk_ai_runs_worker CHECK (
    CASE WHEN executor IN ('platform_worker', 'tenant_worker')
         THEN sensor_id IS NOT NULL OR status IN ('queued', 'canceled', 'refused', 'failed')
         ELSE sensor_id IS NULL
    END) NOT VALID;
ALTER TABLE ai_runs VALIDATE CONSTRAINT chk_ai_runs_worker;

ALTER TABLE ai_runs ADD COLUMN result_digest varchar(71);
ALTER TABLE ai_runs ADD CONSTRAINT chk_ai_runs_result_digest
    CHECK (result_digest IS NULL OR result_digest ~ '^sha256:[0-9a-f]{64}$');
COMMENT ON COLUMN ai_runs.result_digest IS
    'sha256 of the result bytes an AI worker returned for the run; NULL when the run did not run on a worker or has no result yet.';
