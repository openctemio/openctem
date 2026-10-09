DROP INDEX IF EXISTS idx_scope_targets_active_t2;
ALTER TABLE scope_targets
    DROP COLUMN IF EXISTS attestation_requested_at,
    DROP COLUMN IF EXISTS attested_by,
    DROP COLUMN IF EXISTS attested_at;
