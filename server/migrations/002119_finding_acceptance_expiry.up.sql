-- findings.acceptance_expires_at is the end of a risk acceptance: the CI gate
-- stops honouring an accepted finding after it. The approval flow and
-- accepted-risk suppression rules write it; this migration makes sure it never
-- outlives the accepted status and fills it for findings accepted before.
--
-- A finding that leaves accepted (reopen, false positive, expiry controller,
-- any write path) loses its acceptance end, so a later accept starts clean.

CREATE OR REPLACE FUNCTION clear_finding_acceptance_expiry() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.acceptance_expires_at := NULL;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION clear_finding_acceptance_expiry() IS
    'Clears findings.acceptance_expires_at on a row that is not accepted';

DROP TRIGGER IF EXISTS trg_findings_clear_acceptance_expiry ON findings;
CREATE TRIGGER trg_findings_clear_acceptance_expiry
    BEFORE INSERT OR UPDATE ON findings
    FOR EACH ROW
    WHEN (NEW.status::text <> 'accepted' AND NEW.acceptance_expires_at IS NOT NULL)
    EXECUTE FUNCTION clear_finding_acceptance_expiry();

-- Backfill: an accepted finding takes the end of its latest approved
-- acceptance request. Findings accepted without an end (older requests that
-- had none, suppression rules without expiry) stay NULL.
UPDATE findings f
SET acceptance_expires_at = a.expires_at
FROM (
    SELECT DISTINCT ON (tenant_id, finding_id) tenant_id, finding_id, expires_at
    FROM finding_status_approvals
    WHERE status = 'approved' AND requested_status = 'accepted'
    ORDER BY tenant_id, finding_id, approved_at DESC NULLS LAST, created_at DESC
) a
WHERE f.tenant_id = a.tenant_id
  AND f.id = a.finding_id
  AND f.status = 'accepted'
  AND f.acceptance_expires_at IS NULL
  AND a.expires_at IS NOT NULL;

-- Accepted-risk suppression rules: the rule's own expiry.
UPDATE findings f
SET acceptance_expires_at = r.expires_at
FROM finding_suppressions fs
JOIN suppression_rules r ON r.id = fs.suppression_rule_id
WHERE fs.finding_id = f.id
  AND r.tenant_id = f.tenant_id
  AND f.status = 'accepted'
  AND f.acceptance_expires_at IS NULL
  AND r.expires_at IS NOT NULL;
