-- Add index on changes->>'comment_id' for finding_activities table.
-- Used by DeleteByCommentID and UpdateContentByCommentID queries which filter
-- on this JSONB field. Without this index, these operations cause full table scans.
-- Only indexes rows where activity_type = 'comment_added' (partial index) to minimize storage.
CREATE INDEX IF NOT EXISTS idx_finding_activities_comment_id
    ON finding_activities ((changes->>'comment_id'))
    WHERE activity_type = 'comment_added' AND changes->>'comment_id' IS NOT NULL;
