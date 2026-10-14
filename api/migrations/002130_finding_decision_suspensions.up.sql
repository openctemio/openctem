-- A false-positive or accepted decision suspended because the finding's
-- taint source changed (research/134 section 4.1): the finding is open
-- again for review, and the earlier decision stays here to be offered back.
CREATE TABLE IF NOT EXISTS finding_decision_suspensions (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id        uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    prior_status      varchar(32) NOT NULL,
    prior_resolution  text,
    reason            varchar(32) NOT NULL CHECK (reason IN ('taint_source_changed')),
    old_source_hash   varchar(64) NOT NULL,
    new_source_hash   varchar(64) NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_decision_suspensions_finding ON finding_decision_suspensions (tenant_id, finding_id, created_at DESC);
