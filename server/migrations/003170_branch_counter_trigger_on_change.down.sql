DROP TRIGGER IF EXISTS trg_update_branch_finding_counts_update ON public.findings;

CREATE TRIGGER trg_update_branch_finding_counts_update
    AFTER UPDATE OF status, severity, branch_id ON public.findings
    FOR EACH ROW
    WHEN ((new.branch_id IS NOT NULL) OR (old.branch_id IS NOT NULL))
    EXECUTE FUNCTION public.update_branch_finding_counts();
