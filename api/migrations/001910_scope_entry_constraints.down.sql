-- Without the columns a port-limited entry would cover its whole host, so
-- every limited entry is removed (narrowing; the program or person that
-- made it adds it again after an upgrade).
DELETE FROM scope_targets WHERE ports <> '' OR protocol <> '';

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS unique_scope_target;
ALTER TABLE scope_targets ADD CONSTRAINT unique_scope_target UNIQUE (tenant_id, target_type, pattern);
ALTER TABLE scope_targets
    DROP CONSTRAINT IF EXISTS chk_scope_targets_ports,
    DROP CONSTRAINT IF EXISTS chk_scope_targets_protocol,
    DROP COLUMN IF EXISTS protocol,
    DROP COLUMN IF EXISTS ports;
