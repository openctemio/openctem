-- Migration 000137: Auto-update repository stats via triggers
-- Fixes: branch_count, findings counts, component_count all staying at 0

-- =============================================================================
-- 1. Auto-update repository_branches.findings_* when findings change
-- =============================================================================

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

-- Separate triggers for INSERT/UPDATE vs DELETE because
-- DELETE triggers cannot reference NEW in WHEN condition.
DROP TRIGGER IF EXISTS trg_update_branch_finding_counts ON findings;
DROP TRIGGER IF EXISTS trg_update_branch_finding_counts_delete ON findings;

-- INSERT: only NEW available
CREATE TRIGGER trg_update_branch_finding_counts_insert
  AFTER INSERT
  ON findings
  FOR EACH ROW
  WHEN (NEW.branch_id IS NOT NULL)
  EXECUTE FUNCTION update_branch_finding_counts();

-- UPDATE: both NEW and OLD available
CREATE TRIGGER trg_update_branch_finding_counts_update
  AFTER UPDATE OF status, severity, branch_id
  ON findings
  FOR EACH ROW
  WHEN (NEW.branch_id IS NOT NULL OR OLD.branch_id IS NOT NULL)
  EXECUTE FUNCTION update_branch_finding_counts();

-- DELETE: only OLD available
CREATE TRIGGER trg_update_branch_finding_counts_delete
  AFTER DELETE
  ON findings
  FOR EACH ROW
  WHEN (OLD.branch_id IS NOT NULL)
  EXECUTE FUNCTION update_branch_finding_counts();

-- =============================================================================
-- 2. Auto-update asset_repositories.branch_count when branches change
-- =============================================================================

CREATE OR REPLACE FUNCTION update_repository_branch_count()
RETURNS TRIGGER AS $$
DECLARE
  repo_id UUID;
BEGIN
  repo_id := COALESCE(NEW.repository_id, OLD.repository_id);

  UPDATE asset_repositories SET
    branch_count = (SELECT COUNT(*) FROM repository_branches WHERE repository_id = repo_id),
    protected_branch_count = (SELECT COUNT(*) FROM repository_branches WHERE repository_id = repo_id AND is_protected = true)
  WHERE asset_id = repo_id;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_repository_branch_count ON repository_branches;
CREATE TRIGGER trg_update_repository_branch_count
  AFTER INSERT OR DELETE OR UPDATE OF is_protected
  ON repository_branches
  FOR EACH ROW
  EXECUTE FUNCTION update_repository_branch_count();

-- =============================================================================
-- 3. Auto-update asset_repositories.component_count when components change
-- =============================================================================

CREATE OR REPLACE FUNCTION update_repository_component_count()
RETURNS TRIGGER AS $$
DECLARE
  target_asset_id UUID;
BEGIN
  target_asset_id := COALESCE(NEW.asset_id, OLD.asset_id);

  UPDATE asset_repositories SET
    component_count = (SELECT COUNT(*) FROM asset_components WHERE asset_id = target_asset_id),
    vulnerable_component_count = (SELECT COUNT(*) FROM asset_components WHERE asset_id = target_asset_id AND has_known_vulnerabilities = true)
  WHERE asset_id = target_asset_id;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_repository_component_count ON asset_components;
CREATE TRIGGER trg_update_repository_component_count
  AFTER INSERT OR DELETE OR UPDATE OF has_known_vulnerabilities
  ON asset_components
  FOR EACH ROW
  EXECUTE FUNCTION update_repository_component_count();

-- =============================================================================
-- 4. Backfill: recalculate all stale counts from current data
-- =============================================================================

-- Backfill branch finding counts
UPDATE repository_branches rb SET
  findings_total = COALESCE(sub.total, 0),
  findings_critical = COALESCE(sub.critical, 0),
  findings_high = COALESCE(sub.high, 0),
  findings_medium = COALESCE(sub.medium, 0),
  findings_low = COALESCE(sub.low, 0)
FROM (
  SELECT f.branch_id,
    COUNT(*) FILTER (WHERE f.status NOT IN ('resolved','false_positive')) as total,
    COUNT(*) FILTER (WHERE f.severity = 'critical' AND f.status NOT IN ('resolved','false_positive')) as critical,
    COUNT(*) FILTER (WHERE f.severity = 'high' AND f.status NOT IN ('resolved','false_positive')) as high,
    COUNT(*) FILTER (WHERE f.severity = 'medium' AND f.status NOT IN ('resolved','false_positive')) as medium,
    COUNT(*) FILTER (WHERE f.severity = 'low' AND f.status NOT IN ('resolved','false_positive')) as low
  FROM findings f
  WHERE f.branch_id IS NOT NULL
  GROUP BY f.branch_id
) sub
WHERE rb.id = sub.branch_id;

-- Backfill repository branch counts
UPDATE asset_repositories ar SET
  branch_count = COALESCE(sub.total, 0),
  protected_branch_count = COALESCE(sub.protected, 0)
FROM (
  SELECT rb.repository_id,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE rb.is_protected) as protected
  FROM repository_branches rb
  GROUP BY rb.repository_id
) sub
WHERE ar.asset_id = sub.repository_id;

-- Backfill repository component counts
UPDATE asset_repositories ar SET
  component_count = COALESCE(sub.total, 0),
  vulnerable_component_count = COALESCE(sub.vuln, 0)
FROM (
  SELECT ac.asset_id,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE ac.has_known_vulnerabilities) as vuln
  FROM asset_components ac
  GROUP BY ac.asset_id
) sub
WHERE ar.asset_id = sub.asset_id;
