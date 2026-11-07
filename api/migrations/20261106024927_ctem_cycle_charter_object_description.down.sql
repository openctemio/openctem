ALTER TABLE ctem_cycles
    DROP CONSTRAINT IF EXISTS ctem_cycles_description_length,
    DROP COLUMN IF EXISTS description;
