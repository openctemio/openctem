-- Stage streaming (RFC-137): a chained stage takes its predecessor's results
-- task by task while the predecessor still runs. The stage plan records the
-- stream: whether the stage streamed, whether more waves may come, how many
-- waves handed it targets, and when the first did and when it closed.
-- Add-only, constant defaults: no rewrite of the table, existing plans read
-- as barrier plans (not streamed).
ALTER TABLE scan_run_stage_plans
    ADD COLUMN IF NOT EXISTS streamed boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS stream_open boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS waves integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS first_dispatch_at timestamptz,
    ADD COLUMN IF NOT EXISTS closed_at timestamptz;

ALTER TABLE scan_run_stage_plans
    ADD CONSTRAINT chk_scan_run_stage_plans_waves CHECK (waves >= 0),
    ADD CONSTRAINT chk_scan_run_stage_plans_stream CHECK (streamed OR NOT stream_open);

-- The stall repair looks for open streams of running runs.
CREATE INDEX IF NOT EXISTS ix_scan_run_stage_plans_open_stream
    ON scan_run_stage_plans (run_id) WHERE stream_open;
