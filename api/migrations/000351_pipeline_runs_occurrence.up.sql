-- RFC-046 P1.5 (B1, D4): one run per schedule occurrence.
--
-- The scheduler claims an occurrence by compare-and-set on scans.next_run_at
-- (#830), which keeps two scheduler instances from both firing it as long as
-- every path goes through that claim. Nothing in the data said which
-- occurrence a run served, so nothing could prove it either. The run now
-- records it, and the index makes a second run for the same occurrence of
-- the same scan impossible, whichever path creates it.
--
-- Runs not started by the scheduler keep scheduled_for NULL and are not
-- constrained.

ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS scheduled_for TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS uq_pipeline_runs_scan_occurrence
    ON pipeline_runs (scan_id, scheduled_for)
    WHERE scan_id IS NOT NULL AND scheduled_for IS NOT NULL;
