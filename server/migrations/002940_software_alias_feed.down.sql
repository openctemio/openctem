DROP TABLE IF EXISTS software_product_merges;
DELETE FROM software_product_aliases WHERE kind = 'purl';
ALTER TABLE software_product_aliases DROP CONSTRAINT IF EXISTS software_product_aliases_kind_check;
ALTER TABLE software_product_aliases
    ADD CONSTRAINT software_product_aliases_kind_check CHECK (kind IN ('name', 'cpe'));
ALTER TABLE software_product_aliases DROP CONSTRAINT IF EXISTS chk_software_product_aliases_source;
ALTER TABLE software_product_aliases DROP COLUMN IF EXISTS source;
