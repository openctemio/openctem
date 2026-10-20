-- The branch finding counters depend only on a finding's branch, severity and
-- open-ness. The update trigger fired (5 COUNT(*) + 1 UPDATE of
-- repository_branches) on every UPDATE that named one of those columns in its
-- SET list, even when the value was unchanged, which is every re-seen finding
-- on a rescan. Fire only when a value really moved.
DROP TRIGGER IF EXISTS trg_update_branch_finding_counts_update ON public.findings;

CREATE TRIGGER trg_update_branch_finding_counts_update
    AFTER UPDATE OF status, severity, branch_id ON public.findings
    FOR EACH ROW
    WHEN (
        (new.branch_id IS NOT NULL OR old.branch_id IS NOT NULL)
        AND (old.status IS DISTINCT FROM new.status
             OR old.severity IS DISTINCT FROM new.severity
             OR old.branch_id IS DISTINCT FROM new.branch_id)
    )
    EXECUTE FUNCTION public.update_branch_finding_counts();
