-- A pipeline whose repository the code host archived is archived, not stale:
-- it raises no alert and its findings are not marked not observed (the
-- repository's code is still there). Set and cleared by the code host's
-- repository webhook. Nullable, no rewrite.
ALTER TABLE ci_pipelines ADD COLUMN IF NOT EXISTS repository_archived_at timestamptz;
