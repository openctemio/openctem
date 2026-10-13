-- Per-command progress (research/122): the heartbeat reports how many of a
-- held command's targets are finished. A task that keeps finishing targets
-- is slow but alive; one that finishes none for its stall window is stuck
-- and is re-queued, as is one that runs far past its budget.
--
-- Live impact: three nullable columns, no default, no rewrite, no backfill.

ALTER TABLE commands ADD COLUMN progress_done INTEGER;
ALTER TABLE commands ADD COLUMN progress_total INTEGER;
ALTER TABLE commands ADD COLUMN last_progress_at TIMESTAMPTZ;
