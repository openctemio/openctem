ALTER TABLE verified_domains
    DROP CONSTRAINT IF EXISTS chk_verified_domains_jit_role,
    DROP COLUMN IF EXISTS jit_role,
    DROP COLUMN IF EXISTS jit_enabled;
