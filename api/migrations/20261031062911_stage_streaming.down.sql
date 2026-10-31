-- Stage streaming (RFC-137), down.
DROP INDEX IF EXISTS ix_scan_run_stage_plans_open_stream;
ALTER TABLE scan_run_stage_plans
    DROP CONSTRAINT IF EXISTS chk_scan_run_stage_plans_stream,
    DROP CONSTRAINT IF EXISTS chk_scan_run_stage_plans_waves,
    DROP COLUMN IF EXISTS closed_at,
    DROP COLUMN IF EXISTS first_dispatch_at,
    DROP COLUMN IF EXISTS waves,
    DROP COLUMN IF EXISTS stream_open,
    DROP COLUMN IF EXISTS streamed;
