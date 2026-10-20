DROP FUNCTION IF EXISTS command_requeue_backoff_secs(INTEGER);
ALTER TABLE commands DROP COLUMN IF EXISTS requeue_count;
