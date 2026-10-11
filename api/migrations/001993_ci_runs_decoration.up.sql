-- Posting a CI run's verdict to the code host (check run, pull request
-- comment; RFC-077 phase C): '' nothing to post, pending, posting, posted,
-- skipped (no installation, stale pull request head), failed.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS decoration_state VARCHAR(16) NOT NULL DEFAULT '';
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS decoration_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS decoration_detail VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS decoration_updated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_ci_runs_decoration_pending ON ci_runs (decoration_updated_at)
    WHERE decoration_state IN ('pending', 'posting');
