-- Chunked vulnerability bundles (docs/architecture/feed-transfer.md): each
-- chunk upserts its records stamped with the bundle sequence, and the
-- finish step removes what the bundle no longer holds (rows of an older
-- sequence). Platform-wide corpus data: no tenant column, no tenant data.

-- The bundle that last wrote the record (0: written by the whole-bundle
-- importer before chunked bundles).
ALTER TABLE cve_records ADD COLUMN IF NOT EXISTS feed_sequence BIGINT NOT NULL DEFAULT 0
    CONSTRAINT chk_cve_records_feed_sequence CHECK (feed_sequence >= 0);
CREATE INDEX IF NOT EXISTS idx_cve_records_feed_sequence ON cve_records (feed_sequence);

-- range_key is the bundle record id of the range ("<cve>#<digest>"); rows
-- written by the whole-bundle importer have none and are replaced by the
-- next chunked snapshot.
ALTER TABLE vulnerability_affected ADD COLUMN IF NOT EXISTS feed_sequence BIGINT NOT NULL DEFAULT 0
    CONSTRAINT chk_vulnerability_affected_feed_sequence CHECK (feed_sequence >= 0);
ALTER TABLE vulnerability_affected ADD COLUMN IF NOT EXISTS range_key TEXT
    CONSTRAINT chk_vulnerability_affected_range_key CHECK (range_key ~ '^CVE-[0-9]{4}-[0-9]{4,19}#[0-9a-f]{16}$');
CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerability_affected_range_key ON vulnerability_affected (range_key)
    WHERE range_key IS NOT NULL;

-- Products a chunked bundle lists, resolved to global catalog products by
-- the products chunks, so ranges in later chunks (or a resumed run) name
-- only products of the same bundle.
CREATE TABLE IF NOT EXISTS cve_feed_products (
    product_key   TEXT PRIMARY KEY CHECK (length(product_key) BETWEEN 1 AND 300),
    product_id    UUID NOT NULL REFERENCES software_products(id) ON DELETE CASCADE,
    feed_sequence BIGINT NOT NULL CHECK (feed_sequence > 0)
);
CREATE INDEX IF NOT EXISTS idx_cve_feed_products_sequence ON cve_feed_products (feed_sequence);
COMMENT ON TABLE cve_feed_products IS
    'Product keys of the vulnerability bundles and their global catalog products. Platform-wide, no tenant data.';
