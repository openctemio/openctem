-- The unset duplicate/inactive defaults are not restored (the data fix cannot
-- be reversed); only the constraints are removed.
ALTER TABLE sla_policies DROP CONSTRAINT IF EXISTS chk_sla_policies_severity_days;
ALTER TABLE sla_policies DROP CONSTRAINT IF EXISTS chk_sla_policies_default_active;
DROP INDEX IF EXISTS uq_sla_policies_tenant_default;
