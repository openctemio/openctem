-- RFC-046: a run's tasks are the commands whose payload names the run
-- (pipeline_run_id, written by the scan and the pipeline dispatcher). The runs
-- page summarizes the tasks of every run on screen, and cancel and the
-- deadline reaper close them; without an index each read scanned every
-- command of the tenant. One statement per file: CREATE INDEX CONCURRENTLY
-- cannot run inside the implicit transaction of a multi-statement migration,
-- and a plain CREATE INDEX would block command writes (claims, heartbeats)
-- while it builds.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_commands_pipeline_run
    ON commands (tenant_id, (payload->>'pipeline_run_id'))
    WHERE (payload->>'pipeline_run_id') IS NOT NULL;
