-- Remediation campaigns: optimistic concurrency, an honest reconcile order and
-- risk columns that hold risk (research 156 B4, B5, B15).
--
-- version: every full save checks and bumps it, so a stale write (a second
-- tab, the progress reconciler) cannot revert a Cancel or a Pause.
-- last_reconciled_at: the reconciler takes the least recently reconciled
-- campaigns first and stamps every one it visits, changed or not.
-- risk_score_before/after and risk_reduction held finding counts, not risk,
-- and overflowed numeric(5,2) at 1,000 findings: widen them and clear the
-- counts they hold (they were never a risk value).
ALTER TABLE remediation_campaigns
    ADD COLUMN IF NOT EXISTS version integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS last_reconciled_at timestamptz;

ALTER TABLE remediation_campaigns
    ALTER COLUMN risk_score_before TYPE numeric(12,2),
    ALTER COLUMN risk_score_after TYPE numeric(12,2),
    ALTER COLUMN risk_reduction TYPE numeric(12,2);

UPDATE remediation_campaigns
   SET risk_score_before = NULL, risk_score_after = NULL, risk_reduction = NULL
 WHERE risk_score_before IS NOT NULL OR risk_score_after IS NOT NULL OR risk_reduction IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_remediation_campaigns_reconcile
    ON remediation_campaigns (last_reconciled_at NULLS FIRST)
    WHERE status NOT IN ('completed', 'canceled');

-- Priority is one of the API's values. The web once sent 'urgent', which the
-- API does not define; it is the API's 'critical'. The CHECK is added NOT
-- VALID and validated by remediation_campaign_priority_check_validate.
UPDATE remediation_campaigns SET priority = 'critical' WHERE priority = 'urgent';
UPDATE remediation_campaigns SET priority = 'medium'
 WHERE priority NOT IN ('critical', 'high', 'medium', 'low');

ALTER TABLE remediation_campaigns
    ADD CONSTRAINT chk_remediation_campaigns_priority
    CHECK (priority IN ('critical', 'high', 'medium', 'low')) NOT VALID;
