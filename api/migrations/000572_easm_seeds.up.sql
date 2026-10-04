-- EASM seeds (RFC-036 §5.1, §6.3): what the organisation says is its own,
-- from which discovery expands. One row per (tenant, kind, value). Two
-- tenants may seed the same value; nothing relates their rows.
--
-- kind lists every RFC seed kind so later collectors need no migration; the
-- API accepts only the kinds something consumes (root_domain today).
-- Verification is not stored: a root_domain seed is verified while
-- verified_domains holds a verified row for it or a parent, computed on read.
-- attested_by / attested_at record who stated the organisation's authority
-- over the seed, and when (the record RFC-036 §6.3 asks for).
CREATE TABLE IF NOT EXISTS easm_seeds (
    id                UUID        PRIMARY KEY,
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind              TEXT        NOT NULL,
    value             TEXT        NOT NULL,
    label             TEXT        NOT NULL DEFAULT '',
    discovery_enabled BOOLEAN     NOT NULL DEFAULT TRUE,
    attested_by       UUID        REFERENCES users(id) ON DELETE SET NULL,
    attested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by        UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_easm_seeds_tenant_kind_value UNIQUE (tenant_id, kind, value),
    CONSTRAINT chk_easm_seeds_kind CHECK (kind IN (
        'org_name', 'brand', 'root_domain', 'asn', 'cidr', 'cloud_account',
        'github_org', 'mobile_publisher', 'analytics_id', 'favicon_hash')),
    CONSTRAINT chk_easm_seeds_value CHECK (length(value) BETWEEN 1 AND 253),
    CONSTRAINT chk_easm_seeds_label CHECK (length(label) <= 200)
);

CREATE INDEX IF NOT EXISTS idx_easm_seeds_tenant_kind
    ON easm_seeds (tenant_id, kind) WHERE discovery_enabled;
