-- cve_feed_products.product_id references software_products ON DELETE
-- CASCADE: a product fold repoints and deletes by it. One statement
-- (CONCURRENTLY cannot run in a transaction).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_feed_products_product ON cve_feed_products (product_id);
