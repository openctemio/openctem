-- RFC-046 P1.3 (D5): a run that reaches its deadline keeps what it scanned.
--
-- deadline_at is fixed when the run starts: started_at plus the scan timeout
-- (or the 24 h ceiling when the run has no scan), capped at the ceiling. The
-- reaper used to compute the limit from the scan at reap time, so editing a
-- scan timeout moved the deadline of runs already in flight. Runs started
-- before this migration keep NULL and the reaper falls back to that formula.
--
-- unfinished_targets lists the targets of the work still open when the run
-- was settled at its deadline. The next scheduled run of the same scan plans
-- them first (rollover). Bounded by the per-run target cap (10,000).

ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS deadline_at TIMESTAMPTZ;
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS unfinished_targets JSONB;

ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS chk_pipeline_runs_unfinished_targets;
ALTER TABLE pipeline_runs ADD CONSTRAINT chk_pipeline_runs_unfinished_targets
    CHECK (unfinished_targets IS NULL OR jsonb_typeof(unfinished_targets) = 'array');

-- The reaper scans open runs by deadline.
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_open_deadline
    ON pipeline_runs (deadline_at)
    WHERE status IN ('pending', 'running');
