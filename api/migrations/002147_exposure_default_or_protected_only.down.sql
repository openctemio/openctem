CREATE OR REPLACE FUNCTION public.branch_counts_as_exposure(p_branch_id uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
    SELECT COALESCE((
        SELECT b.is_default OR b.is_protected OR b.branch_type IN ('main', 'release')
            OR NOT EXISTS (SELECT 1 FROM repository_branches d
                           WHERE d.repository_id = b.repository_id AND d.is_default)
        FROM repository_branches b WHERE b.id = p_branch_id
    ), TRUE)
$$;
