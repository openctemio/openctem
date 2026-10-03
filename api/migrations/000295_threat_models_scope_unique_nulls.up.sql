-- One threat model per (tenant, scope). The constraint from 000189 did not
-- hold for the tenant-wide model: its scope_ref_id is NULL, and a plain UNIQUE
-- treats NULLs as distinct, so two tenant-wide models could exist for one
-- tenant (RFC-043 P0, docs/architecture/deduplication.md probe P18) and reads
-- picked one of them at random.
--
-- 1. Collapse existing duplicates: keep the most recently generated model per
--    scope. A model's threats are regenerated with it, so the losers' threats
--    (threat_model_threats, ON DELETE CASCADE) carry nothing the kept model
--    does not recompute.
DELETE FROM threat_models tm
USING (
    SELECT id,
           row_number() OVER (
               PARTITION BY tenant_id, scope_type, scope_ref_id
               ORDER BY generated_at DESC, updated_at DESC, id DESC
           ) AS rn
    FROM threat_models
) ranked
WHERE tm.id = ranked.id
  AND ranked.rn > 1;

-- 2. Replace the constraint with one that treats NULL as a value (PG 15+).
ALTER TABLE threat_models
    DROP CONSTRAINT IF EXISTS threat_models_tenant_id_scope_type_scope_ref_id_key;
ALTER TABLE threat_models
    ADD CONSTRAINT uq_threat_models_scope
    UNIQUE NULLS NOT DISTINCT (tenant_id, scope_type, scope_ref_id);
