-- Remediation campaigns hold tasks only: the contract step
-- (docs/architecture/remediation-campaigns.md).
--
-- 1. Convert, once more, what a running campaign tracked through its
--    finding_filter (campaigns created or changed between migration
--    remediation_campaigns_hold_tasks and this release). Idempotent: an
--    already converted campaign changes nothing and is not reported again.
-- 2. The lifecycle is draft, active, completed, canceled. paused and
--    validating become active (a task has its own on-hold state, and every
--    finding is verified on its own), each with an audit row.
-- 3. Drop the conversion functions and the columns that held findings or
--    counted them: finding_filter, finding_count, resolved_count, progress,
--    risk_score_before, risk_score_after, risk_reduction. A campaign's
--    summary is derived from its tasks on every read.
--
-- Upgrade note: destructive (column drop). Stop the API while this runs: an
-- API of the previous release reads the dropped columns.
-- expand-contract-ok: one-step contract (owner rule: minimal back-compat); the API of this release no longer reads the columns, and the previous one must be stopped during the deploy (changelog upgrade note)

-- (Absent when this runs again after its own down: nothing left to convert.)
DO $$
BEGIN
    IF to_regprocedure('remediation_campaigns_to_tasks(boolean)') IS NOT NULL THEN
        PERFORM remediation_campaigns_to_tasks(false);
    END IF;
END $$;

INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, resource_name, changes, severity, message, metadata)
SELECT tenant_id, 'remediation_campaign.status_changed', 'remediation_campaign', id::text, name,
       jsonb_build_object('status', jsonb_build_object('old', status, 'new', 'active')),
       'low',
       format('Remediation campaign status %s is retired: the campaign is active', status),
       jsonb_build_object('source', 'migration', 'trigger', 'status_retired')
  FROM remediation_campaigns
 WHERE status IN ('paused', 'validating');

UPDATE remediation_campaigns
   SET status = 'active', updated_at = now(), version = version + 1
 WHERE status IN ('paused', 'validating');

ALTER TABLE remediation_campaigns
    ADD CONSTRAINT chk_remediation_campaigns_status CHECK (status IN ('draft', 'active', 'completed', 'canceled'));

DROP FUNCTION IF EXISTS remediation_campaigns_to_tasks(boolean);
DROP FUNCTION IF EXISTS remediation_campaign_filter_parse(jsonb);

ALTER TABLE remediation_campaigns
    DROP COLUMN IF EXISTS finding_filter,
    DROP COLUMN IF EXISTS finding_count,
    DROP COLUMN IF EXISTS resolved_count,
    DROP COLUMN IF EXISTS progress,
    DROP COLUMN IF EXISTS risk_score_before,
    DROP COLUMN IF EXISTS risk_score_after,
    DROP COLUMN IF EXISTS risk_reduction;

COMMENT ON TABLE remediation_campaigns IS
    'A program of remediation tasks (remediation_tasks.campaign_id) with one owner and due date; it holds tasks, never findings, and its progress is derived from its tasks.';
