-- Deleting a tenant (or a repository asset) cascades through
-- asset_repositories before repository_branches. The findings deleted in the
-- same cascade fire update_branch_finding_counts(), whose UPDATE of a branch
-- row re-checks repository_branches_repository_id_fkey against a repository
-- row that is already gone, so the whole DELETE failed with a foreign-key
-- violation. Skip branches whose repository no longer exists: they are about
-- to be deleted by the same cascade, so their counters do not matter.

CREATE OR REPLACE FUNCTION update_branch_finding_counts()
RETURNS TRIGGER AS $$
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
          findings_total = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND status NOT IN ('resolved','false_positive')), 0),
          findings_critical = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'critical' AND status NOT IN ('resolved','false_positive')), 0),
          findings_high = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'high' AND status NOT IN ('resolved','false_positive')), 0),
          findings_medium = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'medium' AND status NOT IN ('resolved','false_positive')), 0),
          findings_low = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = OLD.branch_id AND severity = 'low' AND status NOT IN ('resolved','false_positive')), 0)
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
      findings_total = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND status NOT IN ('resolved','false_positive')), 0),
      findings_critical = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'critical' AND status NOT IN ('resolved','false_positive')), 0),
      findings_high = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'high' AND status NOT IN ('resolved','false_positive')), 0),
      findings_medium = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'medium' AND status NOT IN ('resolved','false_positive')), 0),
      findings_low = COALESCE((SELECT COUNT(*) FROM findings WHERE branch_id = target_branch_id AND severity = 'low' AND status NOT IN ('resolved','false_positive')), 0)
    WHERE id = target_branch_id
      AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = repository_branches.repository_id);
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
