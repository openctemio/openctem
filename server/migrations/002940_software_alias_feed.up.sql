-- Feed product aliases (RFC-066 §5.5, alias dictionary): the vulnerability
-- feed ships a signed dictionary that maps the vendor:product strings a CNA
-- writes and package identities (purl) to canonical catalog products. Its
-- rows are global aliases with source 'feed'. A curated alias (code,
-- reviewed) always wins over a feed alias; tenant-private aliases are
-- 'observed'.

ALTER TABLE software_product_aliases
    ADD COLUMN source TEXT NOT NULL DEFAULT 'curated';
UPDATE software_product_aliases SET source = 'observed' WHERE tenant_id IS NOT NULL;
ALTER TABLE software_product_aliases
    ADD CONSTRAINT chk_software_product_aliases_source
    CHECK (source IN ('curated', 'feed', 'observed') AND (tenant_id IS NULL) = (source <> 'observed'));

-- purl: "pkg:<type>/<namespace>/<name>" without version, qualifiers or
-- subpath (lower case).
ALTER TABLE software_product_aliases DROP CONSTRAINT IF EXISTS software_product_aliases_kind_check;
ALTER TABLE software_product_aliases
    ADD CONSTRAINT software_product_aliases_kind_check CHECK (kind IN ('name', 'cpe', 'purl'));

COMMENT ON COLUMN software_product_aliases.source IS
    'curated: the curated list in code; feed: the signed vulnerability feed''s alias dictionary; observed: a tenant-private alias.';

-- Journal of product folds. A fold moves tenant links, findings and VEX
-- statements to the canonical product and deletes the folded one, so each
-- fold records what an operator needs to split it again: the folded
-- identity, the entry that caused it, the versions that moved as they are
-- and the CVEs whose ranges moved. Global catalog data only: no tenant ids.
CREATE TABLE software_product_merges (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    from_product_id   UUID NOT NULL,
    into_product_id   UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    from_identity     TEXT NOT NULL CHECK (length(from_identity) <= 600),
    from_name         TEXT NOT NULL CHECK (length(from_name) <= 400),
    from_source       TEXT NOT NULL CHECK (length(from_source) <= 32),
    alias_kind        TEXT NOT NULL CHECK (length(alias_kind) <= 16),
    alias_value       TEXT NOT NULL CHECK (length(alias_value) <= 600),
    basis             TEXT NOT NULL DEFAULT '' CHECK (length(basis) <= 32),
    moved_version_ids UUID[] NOT NULL DEFAULT '{}',
    cve_ids           TEXT[] NOT NULL DEFAULT '{}',
    merged_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_software_product_merges_into ON software_product_merges (into_product_id);
COMMENT ON TABLE software_product_merges IS
    'Journal of global catalog product folds (alias dictionary, curated list): enough to split a wrong fold. No tenant data.';
