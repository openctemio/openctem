-- VEX statements per tenant (RFC-070 §5.7, §8): a persisted exploitability
-- statement about a vulnerability in a package (all versions, listed
-- versions, or a version range), tenant-wide or for one asset. The platform
-- applies a statement to existing findings and to findings that appear
-- later; findings.vex_statement_id records which statement a finding carries.

CREATE TABLE vex_statements (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vuln_id          TEXT NOT NULL CHECK (vuln_id ~ '^[A-Z0-9][A-Z0-9._:-]{1,127}$'),
    product_id       UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    versions         TEXT[] NOT NULL DEFAULT '{}'
                     CHECK (cardinality(versions) <= 64 AND array_position(versions, NULL) IS NULL),
    version_range    TEXT CHECK (length(version_range) BETWEEN 1 AND 256),
    asset_id         UUID,
    status           TEXT NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
    justification    TEXT CHECK (justification IN ('component_not_present', 'vulnerable_code_not_present',
                         'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary',
                         'inline_mitigations_already_exist')),
    impact_statement TEXT CHECK (length(impact_statement) <= 2000),
    action_statement TEXT CHECK (length(action_statement) <= 2000),
    origin           TEXT NOT NULL CHECK (origin IN ('manual', 'document')),
    document_ref     TEXT CHECK (length(document_ref) <= 512),
    expires_at       TIMESTAMPTZ,
    expired_at       TIMESTAMPTZ,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A not_affected statement says why.
    CONSTRAINT chk_vex_statements_justification CHECK (
        status <> 'not_affected' OR justification IS NOT NULL OR impact_statement IS NOT NULL),
    CONSTRAINT chk_vex_statements_justification_status CHECK (
        justification IS NULL OR status = 'not_affected'),
    -- Listed versions or a range, not both.
    CONSTRAINT chk_vex_statements_version_subject CHECK (cardinality(versions) = 0 OR version_range IS NULL),
    -- The asset is the tenant's own.
    CONSTRAINT fk_vex_statements_tenant_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE
);

-- One statement per subject.
CREATE UNIQUE INDEX ux_vex_statements_subject ON vex_statements (
    tenant_id, vuln_id, product_id, COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid),
    versions, COALESCE(version_range, ''));
CREATE INDEX idx_vex_statements_tenant_product ON vex_statements (tenant_id, product_id);
CREATE INDEX idx_vex_statements_expiry ON vex_statements (expires_at)
    WHERE expires_at IS NOT NULL AND expired_at IS NULL;

COMMENT ON TABLE vex_statements IS
    'Per-tenant VEX statements (RFC-070): vulnerability + package (+ versions or range) (+ asset) -> status. Applied to current and future findings.';
COMMENT ON COLUMN vex_statements.versions IS 'Exact versions (as observed); empty with no range = every version.';
COMMENT ON COLUMN vex_statements.version_range IS 'Comma-separated comparators, all must hold: ">=1.2.0,<1.4.3".';
COMMENT ON COLUMN vex_statements.asset_id IS 'NULL = every asset of the tenant; otherwise only this asset.';
COMMENT ON COLUMN vex_statements.expired_at IS 'When the expiry controller withdrew the statement from its findings.';

-- The product is global (the feed) or the tenant's own: a statement can
-- never point at another tenant's package. (The asset is checked by the
-- composite foreign key; the trigger repeats it for a clear message.)
CREATE FUNCTION vex_statements_scope_check() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ref_tenant UUID;
BEGIN
    SELECT tenant_id INTO ref_tenant FROM software_products WHERE id = NEW.product_id;
    IF ref_tenant IS NOT NULL AND ref_tenant <> NEW.tenant_id THEN
        RAISE EXCEPTION 'vex statement product belongs to another tenant' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.asset_id IS NOT NULL THEN
        SELECT tenant_id INTO ref_tenant FROM assets WHERE id = NEW.asset_id;
        IF ref_tenant IS DISTINCT FROM NEW.tenant_id THEN
            RAISE EXCEPTION 'vex statement asset belongs to another tenant' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_vex_statements_scope BEFORE INSERT OR UPDATE OF tenant_id, product_id, asset_id ON vex_statements
    FOR EACH ROW EXECUTE FUNCTION vex_statements_scope_check();

ALTER TABLE findings ADD COLUMN vex_statement_id UUID REFERENCES vex_statements(id) ON DELETE SET NULL;
CREATE INDEX idx_findings_vex_statement ON findings (vex_statement_id) WHERE vex_statement_id IS NOT NULL;
COMMENT ON COLUMN findings.vex_statement_id IS
    'The tenant VEX statement whose snapshot the vex_* columns hold (NULL: none, or a statement carried by a report or document).';

CREATE FUNCTION findings_vex_statement_scope_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.vex_statement_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM vex_statements s WHERE s.id = NEW.vex_statement_id AND s.tenant_id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'finding vex statement belongs to another tenant' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_findings_vex_statement_scope BEFORE INSERT OR UPDATE OF vex_statement_id, tenant_id ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_vex_statement_scope_check();
