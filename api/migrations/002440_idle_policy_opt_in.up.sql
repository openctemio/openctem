-- The idle-organization policy (docs/architecture/idle-workspaces.md) is
-- opt-in per organization. It used to apply to every organization on the
-- Free plan, which self-service sign-up assigned automatically, so a
-- self-hosted install could make idle organizations read-only without the
-- operator ever choosing that. Now it applies only where a platform
-- administrator turned it on (policy_enabled), and the exemption (the old
-- way to keep one organization out) is no longer needed: off is the default.
--
-- Small table (one row per organization at most). Every existing row starts
-- with the policy off and returns to active, so no organization stays
-- read-only after this migration.

ALTER TABLE tenant_idle_lifecycle
    ADD COLUMN policy_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN policy_reason  text,
    ADD COLUMN policy_set_by  uuid,
    ADD COLUMN policy_set_at  timestamp with time zone,
    ADD CONSTRAINT chk_tenant_idle_lifecycle_policy_reason
        CHECK (policy_reason IS NULL OR char_length(policy_reason) BETWEEN 1 AND 500);

UPDATE tenant_idle_lifecycle SET stage = 'active', stage_changed_at = now() WHERE stage <> 'active';

-- expand-contract-ok: contract step in the same release (owner rule: no release wait); the API stops for this migration (changelog upgrade note), and only the replaced exemption code read these columns.
ALTER TABLE tenant_idle_lifecycle
    DROP CONSTRAINT chk_tenant_idle_lifecycle_exempt_reason,
    DROP COLUMN exempt,
    DROP COLUMN exempt_reason,
    DROP COLUMN exempt_by,
    DROP COLUMN exempt_at;
