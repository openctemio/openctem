-- Stall decided on liveness (research/125): besides finished targets, a
-- heartbeat reports a held command's records, output bytes and CPU time.
-- The platform calls a running task stalled only when none of them moved
-- for its stall window; it then asks the sensor to stop the task and hand
-- back what it finished (stop_requested_at), and re-queues it only if the
-- sensor does not answer within a grace period.
--
-- progress_cpu_mark is the CPU time at the last time it counted as moving
-- (it must grow by a minimum to count: an idle process still uses a little).
--
-- Live impact: nullable columns, no default, no rewrite, no backfill.

ALTER TABLE commands ADD COLUMN progress_records BIGINT;
ALTER TABLE commands ADD COLUMN progress_output_bytes BIGINT;
ALTER TABLE commands ADD COLUMN progress_cpu_ms BIGINT;
ALTER TABLE commands ADD COLUMN progress_cpu_mark BIGINT;
ALTER TABLE commands ADD COLUMN stop_requested_at TIMESTAMPTZ;
