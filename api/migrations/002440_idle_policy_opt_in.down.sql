-- Restores the exemption columns (every organization not exempt) and drops
-- the opt-in policy. Stages stay active; the old sweep selects organizations
-- by plan again.
ALTER TABLE tenant_idle_lifecycle
    ADD COLUMN exempt        boolean NOT NULL DEFAULT false,
    ADD COLUMN exempt_reason text,
    ADD COLUMN exempt_by     uuid,
    ADD COLUMN exempt_at     timestamp with time zone,
    ADD CONSTRAINT chk_tenant_idle_lifecycle_exempt_reason
        CHECK (NOT exempt OR (exempt_reason IS NOT NULL AND char_length(exempt_reason) BETWEEN 1 AND 500));

ALTER TABLE tenant_idle_lifecycle
    DROP CONSTRAINT chk_tenant_idle_lifecycle_policy_reason,
    DROP COLUMN policy_enabled,
    DROP COLUMN policy_reason,
    DROP COLUMN policy_set_by,
    DROP COLUMN policy_set_at;
