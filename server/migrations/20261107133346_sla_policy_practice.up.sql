-- SLA policy practice (docs/architecture/finding-practices.md, "Compliance SLA").
--
-- practice NULL: the policy governs every finding except compliance (the
-- vulnerability policy, as every existing row). practice 'compliance': it
-- governs only compliance findings (benchmark check results). A finding of
-- one kind is never governed by a policy of the other, so compliance windows
-- never reach vulnerability SLA figures and the other way round.
--
-- One tenant-wide default per tenant AND practice: the unique index is
-- rebuilt with the practice. sla_policies is a small configuration table, so
-- the index is built in the migration's transaction.
ALTER TABLE sla_policies ADD COLUMN IF NOT EXISTS practice varchar(16);
ALTER TABLE sla_policies
    ADD CONSTRAINT chk_sla_policies_practice CHECK (practice IS NULL OR practice = 'compliance');

DROP INDEX IF EXISTS uq_sla_policies_tenant_default;
CREATE UNIQUE INDEX uq_sla_policies_tenant_default
    ON sla_policies (tenant_id, COALESCE(practice, ''))
    WHERE is_default AND asset_id IS NULL;

COMMENT ON COLUMN sla_policies.practice IS
    'NULL = governs every finding except compliance; compliance = governs only compliance findings (finding_type compliance).';
