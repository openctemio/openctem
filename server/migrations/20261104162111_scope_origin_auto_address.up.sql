-- A scope entry can be added automatically for an address the
-- organization's in-scope names resolve to when its own network holds it
-- (research/425): origin auto_address, so the Scope page says where it came
-- from. The entry follows the organization's approval policy.

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset', 'connector', 'ci_trust', 'auto_address']));

-- Each pattern is added automatically at most once per tenant: a person who
-- removes such an entry (or the prefix it fell in) is never overridden by
-- the next run.
CREATE TABLE IF NOT EXISTS easm_address_auto_adds (
    tenant_id UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pattern   TEXT        NOT NULL,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, pattern)
);
