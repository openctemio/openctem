-- A finding's retest check: the custom check a person attaches to a finding
-- so that its retest re-runs it (docs/architecture/finding-retest-checks.md).
-- The content stays in the template library (scanner_templates); this table
-- links it to the finding and keeps the check's approval (intrusive checks,
-- bound to a content digest) and calibration (the digest that matched the
-- finding once). New, empty table: no lock on populated data beyond the
-- small unique index on scanner_templates.

CREATE UNIQUE INDEX IF NOT EXISTS ux_scanner_templates_id_tenant ON scanner_templates (id, tenant_id);

CREATE TABLE finding_retest_checks (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id uuid NOT NULL,
    template_id uuid NOT NULL,
    kind varchar(20) NOT NULL,
    assertion jsonb,
    owns_template boolean NOT NULL DEFAULT false,
    tier varchar(2) NOT NULL,
    tier_reason text NOT NULL DEFAULT '',
    approved_digest varchar(80),
    approved_by uuid,
    approved_at timestamptz,
    calibrated_digest varchar(80),
    calibrated_at timestamptz,
    author_id uuid,
    created_by uuid,
    updated_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_finding_retest_checks_finding FOREIGN KEY (finding_id, tenant_id)
        REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
    -- A template in use by a check cannot be deleted from the library.
    CONSTRAINT fk_finding_retest_checks_template FOREIGN KEY (template_id, tenant_id)
        REFERENCES scanner_templates (id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT ux_finding_retest_checks_finding UNIQUE (tenant_id, finding_id),
    CONSTRAINT chk_finding_retest_checks_kind CHECK (kind IN ('nuclei', 'http_assertion')),
    CONSTRAINT chk_finding_retest_checks_tier CHECK (tier IN ('T0', 'T1', 'T2')),
    CONSTRAINT chk_finding_retest_checks_assertion CHECK ((kind = 'http_assertion') = (assertion IS NOT NULL))
);

CREATE INDEX idx_finding_retest_checks_template ON finding_retest_checks (tenant_id, template_id);

COMMENT ON TABLE finding_retest_checks IS 'A finding''s custom retest check: a template of the library, its approval and calibration';

-- Provenance of a retest that ran a check: which check, the exact content
-- digest sent, and the path it had to prove it requested.
ALTER TABLE finding_retests
    ADD COLUMN retest_check_id uuid,
    ADD COLUMN check_digest varchar(80),
    ADD COLUMN check_path text;

ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated'));
