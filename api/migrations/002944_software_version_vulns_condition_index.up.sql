-- software_version_vulns.condition_product_id references software_products
-- ON DELETE SET NULL: a product fold repoints and deletes by it. Partial:
-- few matches carry a condition. One statement (CONCURRENTLY cannot run in a
-- transaction).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_software_version_vulns_condition
    ON software_version_vulns (condition_product_id) WHERE condition_product_id IS NOT NULL;
