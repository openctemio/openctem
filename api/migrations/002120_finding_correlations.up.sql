-- Cross-rule correlation of findings (research/134 section 12). Correlation
-- may reduce noise, never coverage: an auto link makes the member a
-- duplicate of the primary and keeps everything needed to release it; a
-- suggested link changes nothing until a person confirms it.

-- The injection point a web finding was observed at (payload removed), per
-- finding, so findings of different scans can be compared.
CREATE TABLE IF NOT EXISTS finding_injection_points (
    finding_id  uuid PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id    uuid NOT NULL,
    kind        varchar(16) NOT NULL CHECK (kind IN ('dast')),
    point_key   text NOT NULL CHECK (char_length(point_key) BETWEEN 1 AND 4096),
    origin      text NOT NULL CHECK (char_length(origin) BETWEEN 1 AND 512),
    path        text NOT NULL CHECK (char_length(path) BETWEEN 1 AND 2048),
    method      varchar(16) NOT NULL,
    params      text[] NOT NULL DEFAULT '{}' CHECK (cardinality(params) <= 64),
    stripped    text CHECK (stripped IS NULL OR char_length(stripped) <= 2048),
    matched_url text CHECK (matched_url IS NULL OR char_length(matched_url) <= 4096),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_injection_points_asset ON finding_injection_points (tenant_id, asset_id);

CREATE TABLE IF NOT EXISTS finding_correlations (
    id                     uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id              uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    primary_id             uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    member_id              uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    kind                   varchar(16) NOT NULL CHECK (kind IN ('dast')),
    tier                   varchar(16) NOT NULL CHECK (tier IN ('auto', 'suggested')),
    state                  varchar(16) NOT NULL CHECK (state IN ('active', 'released', 'rejected')),
    reason                 varchar(32) NOT NULL,
    point_key              text NOT NULL CHECK (char_length(point_key) <= 4096),
    member_prior_status    varchar(32),
    member_prior_resolution varchar(64),
    primary_prior_severity varchar(16),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    released_at            timestamptz,
    released_reason        varchar(64),
    released_by            uuid REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_finding_correlations_distinct CHECK (primary_id <> member_id)
);
-- A finding is the member of at most one active correlation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_correlations_active_member
    ON finding_correlations (tenant_id, member_id) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_finding_correlations_primary ON finding_correlations (tenant_id, primary_id);
