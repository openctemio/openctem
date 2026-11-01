ALTER TABLE tenant_ai_settings DROP CONSTRAINT IF EXISTS chk_tenant_ai_settings_use_cases_object;
ALTER TABLE tenant_ai_settings DROP COLUMN IF EXISTS use_cases;
