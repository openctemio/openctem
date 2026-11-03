-- External attack surface posture score (docs/architecture/easm-posture.md).
--
-- easm_posture_assets holds the precomputed points of every surface asset
-- per category; a read sums the rows of the assets the reader may see, so
-- the data scope applies on read. easm_posture_state is one row per
-- organization: its refresh schedule, the last computation and the
-- Recalculate now budget.
--
-- Live impact: two new empty tables; rows appear when an organization first
-- opens its posture or a dashboard widget reads it.

CREATE TABLE IF NOT EXISTS easm_posture_state (
    tenant_id         uuid         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    refresh_every     varchar(8)   NOT NULL DEFAULT '6h',
    next_refresh_at   timestamptz,
    computed_at       timestamptz,
    duration_ms       integer      NOT NULL DEFAULT 0,
    assets            integer      NOT NULL DEFAULT 0,
    score             smallint,
    grade             varchar(1),
    previous_score    smallint,
    previous_grade    varchar(1),
    last_error        varchar(200) NOT NULL DEFAULT '',
    failed_at         timestamptz,
    last_requested_at timestamptz,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_easm_posture_state PRIMARY KEY (tenant_id),
    CONSTRAINT chk_easm_posture_state_refresh CHECK (refresh_every IN ('manual', '1h', '6h', '24h')),
    CONSTRAINT chk_easm_posture_state_score CHECK (score IS NULL OR score BETWEEN 0 AND 100),
    CONSTRAINT chk_easm_posture_state_previous CHECK (previous_score IS NULL OR previous_score BETWEEN 0 AND 100),
    CONSTRAINT chk_easm_posture_state_grade CHECK (grade IS NULL OR grade IN ('A', 'B', 'C', 'D', 'F')),
    CONSTRAINT chk_easm_posture_state_previous_grade CHECK (previous_grade IS NULL OR previous_grade IN ('A', 'B', 'C', 'D', 'F'))
);

COMMENT ON TABLE easm_posture_state IS
    'Attack surface posture per organization: refresh schedule, last computation (organization-wide score and grade, previous ones), last failure, last Recalculate now.';

-- The refresher claims due organizations.
CREATE INDEX IF NOT EXISTS idx_easm_posture_state_due
    ON easm_posture_state (next_refresh_at) WHERE next_refresh_at IS NOT NULL;

-- asset_id is the all-zero id for issues without an asset (counted only for
-- readers who see the whole organization). No foreign key to assets: the
-- rows are rebuilt on every refresh and reads join live assets.
CREATE TABLE IF NOT EXISTS easm_posture_assets (
    tenant_id         uuid          NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    asset_id          uuid          NOT NULL,
    asset_name        varchar(255)  NOT NULL DEFAULT '',
    root_domain       varchar(255)  NOT NULL DEFAULT '',
    criticality       varchar(20)   NOT NULL DEFAULT 'medium',
    vuln_points       numeric(14,2) NOT NULL DEFAULT 0,
    hijack_points     numeric(14,2) NOT NULL DEFAULT 0,
    service_points    numeric(14,2) NOT NULL DEFAULT 0,
    storage_points    numeric(14,2) NOT NULL DEFAULT 0,
    misconfig_points  numeric(14,2) NOT NULL DEFAULT 0,
    suspicious_points numeric(14,2) NOT NULL DEFAULT 0,
    vuln_issues       integer       NOT NULL DEFAULT 0,
    hijack_issues     integer       NOT NULL DEFAULT 0,
    service_issues    integer       NOT NULL DEFAULT 0,
    storage_issues    integer       NOT NULL DEFAULT 0,
    misconfig_issues  integer       NOT NULL DEFAULT 0,
    suspicious_issues integer       NOT NULL DEFAULT 0,
    CONSTRAINT pk_easm_posture_assets PRIMARY KEY (tenant_id, asset_id),
    CONSTRAINT chk_easm_posture_assets_criticality CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT chk_easm_posture_assets_points CHECK (vuln_points >= 0 AND hijack_points >= 0 AND service_points >= 0
        AND storage_points >= 0 AND misconfig_points >= 0 AND suspicious_points >= 0),
    CONSTRAINT chk_easm_posture_assets_issues CHECK (vuln_issues >= 0 AND hijack_issues >= 0 AND service_issues >= 0
        AND storage_issues >= 0 AND misconfig_issues >= 0 AND suspicious_issues >= 0)
);

COMMENT ON TABLE easm_posture_assets IS
    'Attack surface posture facts: per surface asset (all-zero id: issues without an asset), its name and root domain, effective criticality, weighted points and issue counts per category.';

CREATE INDEX IF NOT EXISTS idx_easm_posture_assets_root
    ON easm_posture_assets (tenant_id, root_domain);
