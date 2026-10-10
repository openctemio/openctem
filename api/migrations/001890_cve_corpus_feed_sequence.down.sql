DROP TABLE IF EXISTS cve_feed_products;
DROP INDEX IF EXISTS uq_vulnerability_affected_range_key;
ALTER TABLE vulnerability_affected DROP COLUMN IF EXISTS range_key;
ALTER TABLE vulnerability_affected DROP COLUMN IF EXISTS feed_sequence;
DROP INDEX IF EXISTS idx_cve_records_feed_sequence;
ALTER TABLE cve_records DROP COLUMN IF EXISTS feed_sequence;
