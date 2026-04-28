-- Roll back migration 000164. Safe — the index was the only
-- durable change, and tenants.settings.asset_source subtree is
-- ignored by any code compiled without RFC-003 support.

BEGIN;

DROP INDEX IF EXISTS idx_asset_sources_asset_primary;

-- Restore the previous column comment. Best-effort — if the prior
-- migration also touched this comment, the exact text may have
-- drifted; this matches the state we believe existed before 000164.
COMMENT ON COLUMN tenants.settings IS
    'Tenant settings JSONB (typed Settings struct).';

COMMIT;
