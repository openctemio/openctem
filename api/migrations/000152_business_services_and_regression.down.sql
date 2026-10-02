DROP TABLE IF EXISTS finding_regression_events;
ALTER TABLE findings DROP COLUMN IF EXISTS last_reopened_at;
ALTER TABLE findings DROP COLUMN IF EXISTS reopen_count;
ALTER TABLE findings DROP COLUMN IF EXISTS is_regression;
DROP INDEX IF EXISTS idx_findings_regression;
DROP TABLE IF EXISTS business_service_assets;
DROP TABLE IF EXISTS business_services;
