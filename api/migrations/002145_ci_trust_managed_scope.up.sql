-- A CI trust configuration adds the repositories it trusts to the
-- organization's scope (docs/rfcs/RFC-054-scope-model.md, "Repository entries
-- and CI trusts"): each trusted namespace or repository is a repository scope
-- entry linked to the trust, kept in step with it and retired with it.

-- Whether the trust manages scope entries (the "Trust and add to scope"
-- choice). Existing trusts get it on; their entries are created by the
-- backfill command or at their next pipeline run.
ALTER TABLE ci_trust_configs ADD COLUMN IF NOT EXISTS manage_scope BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset', 'connector', 'ci_trust']));

-- One row per repository pattern a trust claims. target_id is the scope
-- entry that carries it: one the trust created (origin ci_trust) or an equal
-- entry that already existed. It is cleared when a person deletes such an
-- existing entry; the next sync creates a managed one again. seen_* is the
-- evidence of the first verified pipeline run under the pattern.
CREATE TABLE IF NOT EXISTS scope_target_ci_trusts (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    trust_config_id    UUID NOT NULL,
    pattern            VARCHAR(500) NOT NULL,
    target_id          UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_at            TIMESTAMPTZ,
    seen_run_id        UUID,
    seen_repository    VARCHAR(500),
    seen_owner_id      VARCHAR(64),
    PRIMARY KEY (tenant_id, trust_config_id, pattern),
    CONSTRAINT fk_scope_target_ci_trusts_config FOREIGN KEY (tenant_id, trust_config_id)
        REFERENCES ci_trust_configs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_scope_target_ci_trusts_target FOREIGN KEY (tenant_id, target_id)
        REFERENCES scope_targets (tenant_id, id) ON DELETE SET NULL (target_id)
);
CREATE INDEX IF NOT EXISTS idx_scope_target_ci_trusts_target ON scope_target_ci_trusts (tenant_id, target_id);
