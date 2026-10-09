-- CVE corpus for inventory matching (RFC-066 §5.3): platform-wide, written
-- only by the NVD feed. Only CVEs with at least one vulnerable CPE statement
-- are kept; one vulnerability_affected row is one affected range of one
-- global catalog product.

CREATE TABLE cve_records (
    cve_id           TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    status           TEXT NOT NULL DEFAULT '' CHECK (length(status) <= 32),
    published_at     TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,
    description      TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
    cvss_score       NUMERIC(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_version     TEXT CHECK (length(cvss_version) <= 8),
    cvss_vector      TEXT CHECK (length(cvss_vector) <= 200),
    severity         TEXT CHECK (severity IN ('none', 'low', 'medium', 'high', 'critical')),
    cwes             TEXT[] NOT NULL DEFAULT '{}',
    synced_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_cve_records_synced ON cve_records (synced_at);
COMMENT ON TABLE cve_records IS
    'CVE corpus for inventory matching (RFC-066), platform-wide, written only by the NVD feed. synced_at drives the matcher''s feed cursor.';

CREATE TABLE vulnerability_affected (
    id                   BIGSERIAL PRIMARY KEY,
    cve_id               TEXT NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    product_id           UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    scheme               TEXT NOT NULL DEFAULT 'generic'
                         CHECK (scheme IN ('generic', 'semver', 'pep440', 'maven', 'npm', 'go', 'deb', 'rpm', 'apk')),
    exact_version        TEXT CHECK (length(exact_version) <= 64),
    v_start              TEXT CHECK (length(v_start) <= 64),
    v_start_incl         BOOLEAN NOT NULL DEFAULT false,
    v_end                TEXT CHECK (length(v_end) <= 64),
    v_end_incl           BOOLEAN NOT NULL DEFAULT false,
    edition              TEXT NOT NULL DEFAULT '' CHECK (length(edition) <= 64),
    target               TEXT NOT NULL DEFAULT '' CHECK (length(target) <= 64),
    condition_product_id UUID REFERENCES software_products(id) ON DELETE SET NULL,
    source               TEXT NOT NULL DEFAULT 'nvd' CHECK (source IN ('nvd')),
    synced_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_vulnerability_affected_shape CHECK (exact_version IS NULL OR (v_start IS NULL AND v_end IS NULL))
);
CREATE INDEX idx_vulnerability_affected_product ON vulnerability_affected (product_id);
CREATE INDEX idx_vulnerability_affected_cve ON vulnerability_affected (cve_id);
COMMENT ON TABLE vulnerability_affected IS
    'One affected range of one global catalog product (RFC-066 §5.3). A CVE may have many; a version is affected when any covers it.';

-- Ranges name global (public) products only.
CREATE FUNCTION vulnerability_affected_global_check() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM software_products WHERE id IN (NEW.product_id, NEW.condition_product_id) AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'vulnerability ranges name global products only' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_vulnerability_affected_global BEFORE INSERT OR UPDATE OF product_id, condition_product_id
    ON vulnerability_affected FOR EACH ROW EXECUTE FUNCTION vulnerability_affected_global_check();

-- The feed is off until a platform admin enables it.
INSERT INTO threat_intel_sync_status (source_name, sync_interval_hours, is_enabled, metadata)
VALUES ('nvd', 24, false, '{}'::jsonb)
ON CONFLICT DO NOTHING;
