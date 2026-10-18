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
