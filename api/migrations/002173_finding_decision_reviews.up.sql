-- A decision (false positive, accepted risk, duplicate) is never reversed by
-- an automatic signal. When a signal says it may be wrong (the taint source of
-- the finding changed, an indicator of compromise matched it), the platform
-- raises a review flag on the finding instead, with a timeline entry; a person
-- with the approve permission decides. The flag clears when the finding's
-- status changes.

CREATE TABLE finding_decision_reviews (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    decision_status VARCHAR(32) NOT NULL
        CONSTRAINT chk_finding_decision_reviews_status CHECK (decision_status IN ('false_positive', 'accepted', 'duplicate')),
    reason          VARCHAR(32) NOT NULL
        CONSTRAINT chk_finding_decision_reviews_reason CHECK (reason IN ('taint_source_changed', 'ioc_match')),
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb
        CONSTRAINT chk_finding_decision_reviews_evidence CHECK (jsonb_typeof(evidence) = 'object' AND pg_column_size(evidence) <= 8192),
    raised_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cleared_at      TIMESTAMPTZ
);

CREATE INDEX idx_finding_decision_reviews_finding ON finding_decision_reviews (tenant_id, finding_id);
-- One open flag per finding and reason.
CREATE UNIQUE INDEX uq_finding_decision_reviews_open
    ON finding_decision_reviews (tenant_id, finding_id, reason) WHERE cleared_at IS NULL;

COMMENT ON TABLE finding_decision_reviews IS
    'Review flags on decided findings raised by automatic signals; a decision is never reversed automatically';

CREATE OR REPLACE FUNCTION clear_finding_decision_reviews()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        UPDATE finding_decision_reviews SET cleared_at = NOW()
        WHERE tenant_id = NEW.tenant_id AND finding_id = NEW.id AND cleared_at IS NULL;
    END IF;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION clear_finding_decision_reviews() IS
    'Clears the open review flags of a finding whose status changed (its decision was revisited)';

CREATE TRIGGER trg_findings_clear_decision_reviews
    AFTER UPDATE OF status ON findings
    FOR EACH ROW
    EXECUTE FUNCTION clear_finding_decision_reviews();

ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened', 'assigned', 'unassigned', 'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked', 'verified', 'remediation_updated', 'metadata_updated', 'acceptance_expired', 'comment_added', 'comment_updated', 'comment_deleted', 'scan_detected', 'auto_resolved', 'auto_reopened', 'linked', 'unlinked', 'sla_warning', 'sla_breach', 'sla_restarted', 'ai_triage_requested', 'ai_triage', 'ai_triage_failed', 'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled', 'retest_requested', 'retest_completed', 'evidence_revealed',
    'decision_review'));
