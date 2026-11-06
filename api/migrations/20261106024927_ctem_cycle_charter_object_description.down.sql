ALTER TABLE ctem_cycles
    DROP CONSTRAINT IF EXISTS ctem_cycles_description_length,
    DROP COLUMN IF EXISTS description,
    DROP CONSTRAINT IF EXISTS ctem_cycles_charter_object,
    ALTER COLUMN charter DROP NOT NULL;
