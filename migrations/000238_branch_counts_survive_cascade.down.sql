-- Restore the 000137 definition.

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
        WHERE id = OLD.branch_id;
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
    WHERE id = target_branch_id;
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
