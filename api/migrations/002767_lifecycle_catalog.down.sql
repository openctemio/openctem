ALTER TABLE findings DROP COLUMN IF EXISTS sub_status_id;
ALTER TABLE IF EXISTS lifecycle_schemes DROP CONSTRAINT IF EXISTS fk_lifecycle_schemes_published;
DROP TABLE IF EXISTS lifecycle_scheme_versions;
DROP FUNCTION IF EXISTS lifecycle_scheme_version_guard();
DROP TABLE IF EXISTS lifecycle_schemes;
DROP TABLE IF EXISTS lifecycle_sub_statuses;
DROP FUNCTION IF EXISTS lifecycle_sub_status_category_guard();
