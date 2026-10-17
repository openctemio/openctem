-- Suppression rules under the approval policy
-- (api/docs/rfcs/RFC-111-approval-policy.md): a rule carries a structured
-- reason code (the finding closure reason catalog of its type) and the tier
-- and number of approvers the policy gave it; each approval is a row in
-- approval_signoffs, and a partial approval is audited as 'signed'.
--
-- Live impact: nullable columns without a default (catalog change); the
-- CHECK constraints are added NOT VALID (no scan) and validated by the next
-- migration. Existing rules keep NULL (they were approved, or are pending
-- under the one-approver rule they were made with until someone approves).

ALTER TABLE suppression_rules
    ADD COLUMN IF NOT EXISTS reason_code varchar(64),
    ADD COLUMN IF NOT EXISTS tier varchar(16),
    ADD COLUMN IF NOT EXISTS required_approvals smallint;

ALTER TABLE suppression_rules DROP CONSTRAINT IF EXISTS chk_suppression_rules_tier;
ALTER TABLE suppression_rules ADD CONSTRAINT chk_suppression_rules_tier
    CHECK (tier IS NULL OR tier IN ('single', 'peer', 'security', 'dual')) NOT VALID;
ALTER TABLE suppression_rules DROP CONSTRAINT IF EXISTS chk_suppression_rules_required;
ALTER TABLE suppression_rules ADD CONSTRAINT chk_suppression_rules_required
    CHECK (required_approvals IS NULL OR required_approvals BETWEEN 1 AND 2) NOT VALID;

ALTER TABLE suppression_rule_audit DROP CONSTRAINT IF EXISTS chk_suppression_rule_audit_action;
ALTER TABLE suppression_rule_audit ADD CONSTRAINT chk_suppression_rule_audit_action
    CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'deleted', 'updated', 'signed')) NOT VALID;

COMMENT ON COLUMN suppression_rules.reason_code IS 'Structured reason of the rule (closure reason catalog of its type); required for rules made through the API';
COMMENT ON COLUMN suppression_rules.tier IS 'Approval tier the policy gave the rule: peer, security or dual (RFC-111)';
COMMENT ON COLUMN suppression_rules.required_approvals IS 'People other than the requester who must approve the rule';
