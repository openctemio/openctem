-- Edge protection vendor of a pair's last outcome (RFC-093): when the pair's
-- last outcome is edge_blocked or edge_challenged, the sensor may name the
-- edge protection that answered in the service's place. A short lower-case
-- token, shown as text only; NULL when unknown or when the last outcome is
-- anything else (every settlement rewrites it, so a later success clears it).
--
-- Live impact: nullable column without a default, catalog-only change, no
-- table rewrite, no backfill.

ALTER TABLE asset_coverage
    ADD COLUMN IF NOT EXISTS last_edge_vendor text NULL
    CONSTRAINT chk_asset_coverage_last_edge_vendor
    CHECK (last_edge_vendor IS NULL OR char_length(last_edge_vendor) <= 32);
