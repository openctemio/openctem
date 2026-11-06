-- A branch counts as exposure (findings seen there are organization findings,
-- not branch-only) when it is the default branch or a protected one, or while
-- the repository has no known default branch. A branch type guessed from the
-- name ("main", "release/...") no longer counts: anyone who can push can
-- create "release/x", so a name is not a trust signal. Findings already
-- promoted stay promoted; this changes only what promotes from now on.
CREATE OR REPLACE FUNCTION public.branch_counts_as_exposure(p_branch_id uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT COALESCE((
        SELECT b.is_default OR b.is_protected
            OR NOT EXISTS (SELECT 1 FROM repository_branches d
                           WHERE d.repository_id = b.repository_id AND d.is_default)
        FROM repository_branches b WHERE b.id = p_branch_id
    ), TRUE)
$$;
