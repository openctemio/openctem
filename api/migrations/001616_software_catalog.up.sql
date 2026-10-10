-- Software catalog and per-tenant software links (RFC-066 §5).
--
-- A catalog row is global (tenant_id NULL) only when its identity is public:
-- the curated product list in code or the vulnerability feed. Everything a
-- tenant observes that is not public is a tenant-private row, so one
-- tenant's observation never reveals anything to another. Versions of a
-- global product are global; versions of a private product are private.

CREATE TABLE software_products (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID REFERENCES tenants(id) ON DELETE CASCADE,
    part           CHAR(1) NOT NULL CHECK (part IN ('a', 'o', 'h')),
    vendor         TEXT NOT NULL DEFAULT '' CHECK (length(vendor) <= 128),
    name           TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    cpe_vendor     TEXT CHECK (length(cpe_vendor) BETWEEN 1 AND 128),
    cpe_product    TEXT CHECK (length(cpe_product) BETWEEN 1 AND 128),
    purl_type      TEXT CHECK (length(purl_type) <= 32),
    purl_namespace TEXT CHECK (length(purl_namespace) <= 256),
    purl_name      TEXT CHECK (length(purl_name) <= 256),
    source         TEXT NOT NULL CHECK (source IN ('curated', 'nvd', 'observed')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A global product comes from a public source, never from an observation.
    CONSTRAINT chk_software_products_scope CHECK ((tenant_id IS NULL) = (source <> 'observed')),
    CONSTRAINT chk_software_products_cpe_pair CHECK ((cpe_vendor IS NULL) = (cpe_product IS NULL)),
    CONSTRAINT uq_software_products_id_tenant UNIQUE (id, tenant_id)
);
CREATE UNIQUE INDEX ux_software_products_global_cpe ON software_products (part, cpe_vendor, cpe_product)
    WHERE tenant_id IS NULL AND cpe_vendor IS NOT NULL;
CREATE UNIQUE INDEX ux_software_products_tenant_cpe ON software_products (tenant_id, part, cpe_vendor, cpe_product)
    WHERE tenant_id IS NOT NULL AND cpe_vendor IS NOT NULL;
CREATE UNIQUE INDEX ux_software_products_tenant_name ON software_products (tenant_id, lower(name))
    WHERE tenant_id IS NOT NULL AND cpe_vendor IS NULL;
COMMENT ON TABLE software_products IS
    'Software catalog (RFC-066). tenant_id NULL = public identity (curated list, vulnerability feed); otherwise private to that tenant. Never listed by any API.';

CREATE TABLE software_product_aliases (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    tenant_id  UUID REFERENCES tenants(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('name', 'cpe')),
    value      TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 256 AND value = lower(value)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ux_software_product_aliases_global ON software_product_aliases (kind, value) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX ux_software_product_aliases_tenant ON software_product_aliases (tenant_id, kind, value) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_software_product_aliases_product ON software_product_aliases (product_id);
COMMENT ON TABLE software_product_aliases IS
    'Names and CPE vendor:product pairs a catalog product is known under (RFC-066). Same scope as the product.';

CREATE TABLE software_versions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_id UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    tenant_id  UUID REFERENCES tenants(id) ON DELETE CASCADE,
    raw        TEXT NOT NULL CHECK (length(raw) <= 64),
    normalized TEXT CHECK (length(normalized) <= 160),
    scheme     TEXT NOT NULL DEFAULT 'generic'
               CHECK (scheme IN ('generic', 'semver', 'pep440', 'maven', 'npm', 'go', 'deb', 'rpm', 'apk')),
    qualifier  TEXT NOT NULL DEFAULT '' CHECK (length(qualifier) <= 64),
    edition    TEXT NOT NULL DEFAULT '' CHECK (length(edition) <= 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ux_software_versions_identity
    ON software_versions (product_id, scheme, COALESCE(normalized, 'raw:' || raw), qualifier, edition);
COMMENT ON TABLE software_versions IS
    'Each version of a catalog product once (RFC-066). normalized NULL = the version does not parse and never matches; raw '''' = version unknown. qualifier = distribution build kept apart from the upstream version.';

CREATE TABLE asset_software (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id            UUID NOT NULL,
    product_id          UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    software_version_id UUID NOT NULL REFERENCES software_versions(id) ON DELETE CASCADE,
    location            TEXT NOT NULL DEFAULT '' CHECK (length(location) <= 64),
    port                INTEGER CHECK (port BETWEEN 0 AND 65535),
    transport           TEXT CHECK (transport IN ('tcp', 'udp', 'sctp')),
    source              TEXT NOT NULL CHECK (source IN ('technology', 'service', 'open_port', 'os')),
    evidence            TEXT NOT NULL DEFAULT '' CHECK (length(evidence) <= 512),
    confidence          SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_asset_software_tenant_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_asset_software UNIQUE (tenant_id, asset_id, software_version_id, location)
);
CREATE INDEX idx_asset_software_asset ON asset_software (tenant_id, asset_id);
CREATE INDEX idx_asset_software_version ON asset_software (software_version_id);
CREATE INDEX idx_asset_software_product ON asset_software (tenant_id, product_id, asset_id, location);
COMMENT ON TABLE asset_software IS
    'An asset runs this catalog version at this location (RFC-066). superseded_at: a newer version of the same product was seen at the same location.';

-- Scope consistency: an alias or version has its product's scope, and a
-- tenant links only global rows or its own private rows. A composite foreign
-- key cannot express this because global rows have a NULL tenant.
CREATE FUNCTION software_catalog_scope_check() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    product_tenant UUID;
    version_tenant UUID;
    version_product UUID;
BEGIN
    SELECT tenant_id INTO product_tenant FROM software_products WHERE id = NEW.product_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'software product % does not exist', NEW.product_id USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF TG_TABLE_NAME = 'asset_software' THEN
        IF product_tenant IS NOT NULL AND product_tenant <> NEW.tenant_id THEN
            RAISE EXCEPTION 'software product belongs to another tenant' USING ERRCODE = 'check_violation';
        END IF;
        SELECT tenant_id, product_id INTO version_tenant, version_product
            FROM software_versions WHERE id = NEW.software_version_id;
        IF version_product IS DISTINCT FROM NEW.product_id THEN
            RAISE EXCEPTION 'software version belongs to another product' USING ERRCODE = 'check_violation';
        END IF;
        IF version_tenant IS NOT NULL AND version_tenant <> NEW.tenant_id THEN
            RAISE EXCEPTION 'software version belongs to another tenant' USING ERRCODE = 'check_violation';
        END IF;
    ELSIF product_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION '% scope differs from its product', TG_TABLE_NAME USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_software_product_aliases_scope BEFORE INSERT OR UPDATE OF product_id, tenant_id
    ON software_product_aliases FOR EACH ROW EXECUTE FUNCTION software_catalog_scope_check();
CREATE TRIGGER trg_software_versions_scope BEFORE INSERT OR UPDATE OF product_id, tenant_id
    ON software_versions FOR EACH ROW EXECUTE FUNCTION software_catalog_scope_check();
CREATE TRIGGER trg_asset_software_scope BEFORE INSERT OR UPDATE OF product_id, software_version_id, tenant_id
    ON asset_software FOR EACH ROW EXECUTE FUNCTION software_catalog_scope_check();
