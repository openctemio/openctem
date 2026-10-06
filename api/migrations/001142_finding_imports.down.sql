DROP INDEX IF EXISTS idx_assets_tenant_import;
ALTER TABLE assets DROP COLUMN IF EXISTS import_id;
DROP TABLE IF EXISTS finding_imports;
