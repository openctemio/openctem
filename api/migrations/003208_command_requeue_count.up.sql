-- Every path that returns a command to pending counts here, so a command that
-- is handed back, refused, unclaimed or re-queued over and over is delayed and
-- finally failed instead of cycling forever (dispatch_attempts keeps its own
-- meaning: work a sensor took and lost). Nullable-free column with a constant
-- default: no table rewrite.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS requeue_count INTEGER NOT NULL DEFAULT 0;

-- Seconds a command waits before it is offered again after its n-th re-queue:
-- none for the first, then 5 s doubling, at most 5 minutes.
CREATE OR REPLACE FUNCTION command_requeue_backoff_secs(n INTEGER) RETURNS INTEGER
    LANGUAGE sql IMMUTABLE
    AS $$ SELECT CASE WHEN n <= 1 THEN 0 ELSE LEAST(300, 5 * (2 ^ LEAST(n - 2, 10))::INTEGER) END $$;
