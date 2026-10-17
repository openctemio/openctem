-- One SQL definition of an open finding, the same set as the Go one
-- (pkg/domain/vulnerability status_sets.go, OpenStatuses): a DB test fails when
-- the two disagree. The repository branch counters now count open findings
-- only, so accepted risks, duplicates and pentest drafts no longer inflate them.

CREATE OR REPLACE FUNCTION is_open_finding_status(p_status text)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT p_status IN ('new', 'confirmed', 'in_progress', 'fix_applied', 'validated_fixed', 'not_observed')
$$;

COMMENT ON FUNCTION is_open_finding_status(text) IS
    'True for a finding status that still needs work (the Open lens); same set as vulnerability.OpenStatuses';

CREATE OR REPLACE FUNCTION update_branch_finding_counts()
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
$function$;

-- Recount every branch with the new definition.
UPDATE repository_branches rb SET
    findings_total = c.total, findings_critical = c.critical, findings_high = c.high,
    findings_medium = c.medium, findings_low = c.low
FROM (
    SELECT rb2.id,
        COUNT(f.id) FILTER (WHERE is_open_finding_status(f.status)) AS total,
        COUNT(f.id) FILTER (WHERE is_open_finding_status(f.status) AND f.severity = 'critical') AS critical,
        COUNT(f.id) FILTER (WHERE is_open_finding_status(f.status) AND f.severity = 'high') AS high,
        COUNT(f.id) FILTER (WHERE is_open_finding_status(f.status) AND f.severity = 'medium') AS medium,
        COUNT(f.id) FILTER (WHERE is_open_finding_status(f.status) AND f.severity = 'low') AS low
    FROM repository_branches rb2
    LEFT JOIN findings f ON f.branch_id = rb2.id
    GROUP BY rb2.id
) c
WHERE rb.id = c.id
  AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = rb.repository_id);
