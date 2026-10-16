-- Approval policy (api/docs/rfcs/RFC-111-approval-policy.md): a finding
-- status request records the tier, risk class and number of approvers the
-- policy evaluator gave it, the evaluation itself, and the facts it was
-- decided on (the baseline of the material-change check). Sign-offs of
-- requests that need more than one approver live in approval_signoffs.
--
-- Live impact: nullable columns without a default (a catalog change, no
-- rewrite); two CHECK constraints added NOT VALID (no scan; the next
-- migration validates them); one new empty table.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS tier varchar(16),
    ADD COLUMN IF NOT EXISTS risk_class varchar(16),
    ADD COLUMN IF NOT EXISTS required_approvals smallint,
    ADD COLUMN IF NOT EXISTS policy_eval jsonb,
    ADD COLUMN IF NOT EXISTS decision_facts jsonb;

ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_tier;
ALTER TABLE finding_status_approvals ADD CONSTRAINT chk_finding_status_approvals_tier
    CHECK (tier IS NULL OR tier IN ('single', 'peer', 'security', 'dual')) NOT VALID;
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_required;
ALTER TABLE finding_status_approvals ADD CONSTRAINT chk_finding_status_approvals_required
    CHECK (required_approvals IS NULL OR required_approvals BETWEEN 0 AND 2) NOT VALID;

COMMENT ON COLUMN finding_status_approvals.tier IS 'Approval tier the policy gave the request: single, peer, security or dual (RFC-111)';
COMMENT ON COLUMN finding_status_approvals.risk_class IS 'Risk class of the finding when requested: standard, high or critical';
COMMENT ON COLUMN finding_status_approvals.required_approvals IS 'People other than the requester who must sign off (0 single, 1 peer/security, 2 dual)';
COMMENT ON COLUMN finding_status_approvals.policy_eval IS 'The policy evaluation at request time (tier, class, reasons), shown to approvers and kept as evidence';
COMMENT ON COLUMN finding_status_approvals.decision_facts IS 'Finding facts (severity, priority, KEV, EPSS, exploit, exposure) the decision was made on; baseline of the material-change check';

-- One row per person who approved a request that needs sign-offs. The
-- subject is a finding status request, a group exception (approval batch) or
-- a suppression rule; the row is always read by (tenant_id, subject_type,
-- subject_id).
CREATE TABLE IF NOT EXISTS approval_signoffs (
    id            uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_type  varchar(32) NOT NULL,
    subject_id    uuid        NOT NULL,
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    security_pool boolean     NOT NULL DEFAULT false,
    pool_fallback boolean     NOT NULL DEFAULT false,
    step_up       boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_approval_signoffs_subject_type
        CHECK (subject_type IN ('finding_approval', 'approval_batch', 'suppression_rule')),
    CONSTRAINT uq_approval_signoffs_subject_user UNIQUE (tenant_id, subject_type, subject_id, user_id)
);

COMMENT ON TABLE approval_signoffs IS
    'Sign-offs of approval requests that need more than one approver (RFC-111); one per person and request';
COMMENT ON COLUMN approval_signoffs.security_pool IS 'The signer was in the security pool when they signed';
COMMENT ON COLUMN approval_signoffs.pool_fallback IS 'The security pool had nobody eligible; the approver pool stood in';
COMMENT ON COLUMN approval_signoffs.step_up IS 'The signer had re-authenticated recently when they signed';
