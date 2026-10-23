-- Restores the per-row branch counter triggers (see the up migration).

DROP TRIGGER IF EXISTS trg_findings_branch_counts_insert ON findings;
DROP TRIGGER IF EXISTS trg_findings_branch_counts_delete ON findings;
DROP TRIGGER IF EXISTS trg_findings_branch_counts_update ON findings;
DROP FUNCTION IF EXISTS branch_finding_counts_from_rows();
DROP FUNCTION IF EXISTS branch_finding_counts_from_update();
DROP FUNCTION IF EXISTS refresh_branch_finding_counts(uuid[]);

CREATE OR REPLACE FUNCTION public.update_branch_finding_counts()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
  target_branch_id UUID;
BEGIN
  -- Determine which branch_id to update
  IF TG_OP = 'DELETE' THEN
    target_branch_id := OLD.branch_id;
  ELSIF TG_OP = 'UPDATE' THEN
    -- Update both old and new branch if changed
    IF OLD.branch_id IS DISTINCT FROM NEW.branch_id THEN
      IF OLD.branch_id IS NOT NULL THEN
        UPDATE repository_branches SET
          findings_total = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND is_open_finding_status(status)), 0),
          findings_critical = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'critical' AND is_open_finding_status(status)), 0),
          findings_high = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'high' AND is_open_finding_status(status)), 0),
          findings_medium = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'medium' AND is_open_finding_status(status)), 0),
          findings_low = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'low' AND is_open_finding_status(status)), 0)
        WHERE id = OLD.branch_id
          AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = repository_branches.repository_id);
      END IF;
    END IF;
    target_branch_id := NEW.branch_id;
  ELSE
    target_branch_id := NEW.branch_id;
  END IF;
  -- Update target branch counts
  IF target_branch_id IS NOT NULL THEN
    UPDATE repository_branches SET
      findings_total = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND is_open_finding_status(status)), 0),
      findings_critical = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'critical' AND is_open_finding_status(status)), 0),
      findings_high = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'high' AND is_open_finding_status(status)), 0),
      findings_medium = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'medium' AND is_open_finding_status(status)), 0),
      findings_low = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'low' AND is_open_finding_status(status)), 0)
    WHERE id = target_branch_id
      AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = repository_branches.repository_id);
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$function$
;

CREATE TRIGGER trg_update_branch_finding_counts_insert
    AFTER INSERT ON public.findings
    FOR EACH ROW
    WHEN (new.branch_id IS NOT NULL)
    EXECUTE FUNCTION public.update_branch_finding_counts();

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

CREATE TRIGGER trg_update_branch_finding_counts_delete
    AFTER DELETE ON public.findings
    FOR EACH ROW
    WHEN (old.branch_id IS NOT NULL)
    EXECUTE FUNCTION public.update_branch_finding_counts();
