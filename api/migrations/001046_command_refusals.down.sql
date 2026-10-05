ALTER TABLE commands
    DROP CONSTRAINT IF EXISTS chk_commands_refusals_shape,
    DROP COLUMN IF EXISTS refusals,
    DROP COLUMN IF EXISTS refused_by;
