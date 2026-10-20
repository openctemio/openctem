-- Asset risk change requests (api/docs/architecture/asset-risk-governance.md).
--
-- An edit that lowers an asset's exposure, criticality or crown-jewel flag and
-- would lower an open P0/P1 finding on it waits here for the approval the
-- organization's policy asks for (one pending request per asset). Each
-- sign-off is a row in approval_signoffs (subject_type asset_risk_request).
--
-- Live impact: one new empty table and a re-added CHECK on the small
-- approval_signoffs table (one row per approval given).

CREATE TABLE IF NOT EXISTS asset_risk_requests (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL,
    asset_id              uuid        NOT NULL,
    requested_exposure    varchar(20) NOT NULL,
    requested_criticality varchar(20) NOT NULL,
    requested_crown_jewel boolean     NOT NULL,
    previous_exposure     varchar(20) NOT NULL,
    previous_criticality  varchar(20) NOT NULL,
    previous_crown_jewel  boolean     NOT NULL,
    lowered_fields        text[]      NOT NULL,
    reason                text        NOT NULL,
    impact                jsonb       NOT NULL DEFAULT '{}'::jsonb,
    requested_by          uuid,
    status                varchar(16) NOT NULL DEFAULT 'pending',
    tier                  varchar(16) NOT NULL,
    required_approvals    smallint    NOT NULL DEFAULT 1,
    decide_by             timestamptz NOT NULL,
    decided_by            uuid,
    decided_at            timestamptz,
    decision_note         text,
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_risk_requests PRIMARY KEY (id),
    CONSTRAINT fk_asset_risk_requests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_risk_requests_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_risk_requests_requested_by FOREIGN KEY (requested_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_asset_risk_requests_decided_by FOREIGN KEY (decided_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_asset_risk_requests_exposure
        CHECK (requested_exposure IN ('public', 'restricted', 'private', 'isolated', 'unknown')
               AND previous_exposure IN ('public', 'restricted', 'private', 'isolated', 'unknown')),
    CONSTRAINT chk_asset_risk_requests_criticality
        CHECK (requested_criticality IN ('critical', 'high', 'medium', 'low', 'none')
               AND previous_criticality IN ('critical', 'high', 'medium', 'low', 'none')),
    CONSTRAINT chk_asset_risk_requests_lowered CHECK (cardinality(lowered_fields) >= 1),
    CONSTRAINT chk_asset_risk_requests_status
        CHECK (status IN ('pending', 'approved', 'rejected', 'canceled', 'expired')),
    CONSTRAINT chk_asset_risk_requests_tier CHECK (tier IN ('single', 'peer', 'security', 'dual')),
    CONSTRAINT chk_asset_risk_requests_required CHECK (required_approvals BETWEEN 1 AND 3),
    CONSTRAINT chk_asset_risk_requests_reason CHECK (btrim(reason) <> '' AND char_length(reason) <= 1000)
);

COMMENT ON TABLE asset_risk_requests IS
    'Edits that lower an asset''s exposure, criticality or crown-jewel flag and wait for the approval the organization''s policy asks for; sign-offs in approval_signoffs';

CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_risk_requests_pending
    ON asset_risk_requests (tenant_id, asset_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_asset_risk_requests_asset
    ON asset_risk_requests (tenant_id, asset_id, created_at DESC);

ALTER TABLE approval_signoffs DROP CONSTRAINT IF EXISTS chk_approval_signoffs_subject_type;
ALTER TABLE approval_signoffs ADD CONSTRAINT chk_approval_signoffs_subject_type
    CHECK (subject_type IN ('finding_approval', 'approval_batch', 'suppression_rule', 'severity_request', 'asset_risk_request'));
