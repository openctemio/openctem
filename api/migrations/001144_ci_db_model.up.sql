-- expand-contract-ok: one-step contract (owner rule: minimal back-compat; upgrade note in the changelog). During a rolling deploy an old pod that reads ci_gate_policies.scope_id or ci_gate_overrides.created_by_email fails the CI gate evaluation and the gate-policy and break-glass console calls until it is replaced; the CI exchange and uploads keep working.
-- CI data model fixes (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
-- "Data model"). No table is renamed.
--
-- 1. ci_runs and ci_pipelines reference their trust configuration with the
--    tenant: a row can never point at another tenant's configuration.
--    Deleting a configuration keeps the runs and pipelines as history
--    (ON DELETE SET NULL on trust_config_id only). The constraints are added
--    NOT VALID here (no table scan under this transaction's lock) and
--    validated by 001145. A cross-tenant reference cannot be written by the
--    application; any that exists is cleared first (it names nothing the row's
--    tenant owns).
-- 2. ci_gate_policies: the polymorphic scope_id becomes repository_asset_id
--    or business_unit_id, each with a composite foreign key (cascade): a
--    repository's policy follows the repository on merge and goes with it on
--    delete, instead of pointing at nothing. Policies whose repository or
--    business unit no longer exists are deleted (they could not apply).
--    business_units gains UNIQUE (tenant_id, id) as the key they reference.
-- 3. ci_gate_overrides.created_by_email is dropped: the creator is created_by
--    (a user id, resolved when read), and the audit log records the actor. A
--    person's email is no longer copied into CI tables.
--
-- Live impact: small tables except ci_runs; ci_runs gets one UPDATE limited
-- to cross-tenant rows (none expected) and a NOT VALID constraint.

-- 1 -------------------------------------------------------------------------
UPDATE ci_runs r SET trust_config_id = NULL
 WHERE r.trust_config_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM ci_trust_configs c WHERE c.id = r.trust_config_id AND c.tenant_id = r.tenant_id);
UPDATE ci_pipelines p SET trust_config_id = NULL
 WHERE p.trust_config_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM ci_trust_configs c WHERE c.id = p.trust_config_id AND c.tenant_id = p.tenant_id);

ALTER TABLE ci_runs DROP CONSTRAINT IF EXISTS ci_runs_trust_config_id_fkey;
ALTER TABLE ci_runs ADD CONSTRAINT fk_ci_runs_trust_config
    FOREIGN KEY (tenant_id, trust_config_id) REFERENCES ci_trust_configs (tenant_id, id)
    ON DELETE SET NULL (trust_config_id) NOT VALID;

ALTER TABLE ci_pipelines DROP CONSTRAINT IF EXISTS ci_pipelines_trust_config_id_fkey;
ALTER TABLE ci_pipelines ADD CONSTRAINT fk_ci_pipelines_trust_config
    FOREIGN KEY (tenant_id, trust_config_id) REFERENCES ci_trust_configs (tenant_id, id)
    ON DELETE SET NULL (trust_config_id) NOT VALID;

-- 2 -------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_business_units_tenant_id') THEN
        ALTER TABLE business_units ADD CONSTRAINT uq_business_units_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

ALTER TABLE ci_gate_policies
    ADD COLUMN IF NOT EXISTS repository_asset_id UUID,
    ADD COLUMN IF NOT EXISTS business_unit_id    UUID;

UPDATE ci_gate_policies SET repository_asset_id = scope_id WHERE scope_type = 'repository';
UPDATE ci_gate_policies SET business_unit_id    = scope_id WHERE scope_type = 'business_unit';

DO $$
DECLARE
    n integer;
BEGIN
    DELETE FROM ci_gate_policies p
     WHERE (p.scope_type = 'repository' AND NOT EXISTS (
                SELECT 1 FROM assets a WHERE a.tenant_id = p.tenant_id AND a.id = p.repository_asset_id))
        OR (p.scope_type = 'business_unit' AND NOT EXISTS (
                SELECT 1 FROM business_units b WHERE b.tenant_id = p.tenant_id AND b.id = p.business_unit_id));
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n > 0 THEN
        RAISE NOTICE 'ci_gate_policies: % polic(ies) of a deleted repository or business unit removed', n;
    END IF;
END $$;

DROP INDEX IF EXISTS uq_ci_gate_policies_scope;
ALTER TABLE ci_gate_policies DROP CONSTRAINT IF EXISTS chk_ci_gate_policies_scope;
ALTER TABLE ci_gate_policies DROP COLUMN IF EXISTS scope_id;

ALTER TABLE ci_gate_policies ADD CONSTRAINT chk_ci_gate_policies_scope CHECK (
       (scope_type = 'tenant'        AND repository_asset_id IS NULL     AND business_unit_id IS NULL)
    OR (scope_type = 'repository'    AND repository_asset_id IS NOT NULL AND business_unit_id IS NULL)
    OR (scope_type = 'business_unit' AND business_unit_id IS NOT NULL    AND repository_asset_id IS NULL));
ALTER TABLE ci_gate_policies ADD CONSTRAINT fk_ci_gate_policies_repository
    FOREIGN KEY (tenant_id, repository_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE ci_gate_policies ADD CONSTRAINT fk_ci_gate_policies_business_unit
    FOREIGN KEY (tenant_id, business_unit_id) REFERENCES business_units (tenant_id, id) ON DELETE CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ci_gate_policies_scope ON ci_gate_policies
    (tenant_id, scope_type, COALESCE(repository_asset_id, business_unit_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- 3 -------------------------------------------------------------------------
ALTER TABLE ci_gate_overrides DROP COLUMN IF EXISTS created_by_email;

COMMENT ON COLUMN ci_gate_policies.repository_asset_id IS 'The repository of a repository-scope policy (RFC-051).';
COMMENT ON COLUMN ci_gate_policies.business_unit_id IS 'The business unit of a business-unit-scope policy (RFC-051).';
