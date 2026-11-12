ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS chk_tenants_region,
    DROP COLUMN IF EXISTS region;
