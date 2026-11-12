-- Compliance policies cannot survive the down: they would govern every
-- finding. They are removed (configuration only; findings keep their
-- deadlines).
DELETE FROM sla_policies WHERE practice IS NOT NULL;
DROP INDEX IF EXISTS uq_sla_policies_tenant_default;
CREATE UNIQUE INDEX uq_sla_policies_tenant_default
    ON sla_policies (tenant_id)
    WHERE is_default AND asset_id IS NULL;
ALTER TABLE sla_policies DROP CONSTRAINT IF EXISTS chk_sla_policies_practice;
ALTER TABLE sla_policies DROP COLUMN IF EXISTS practice;
