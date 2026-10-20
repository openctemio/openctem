-- The dropped twins are recreated; foreign keys stay on the surviving indexes.
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_id_tenant ON findings (id, tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_tenant_id_id ON groups (tenant_id, id);
ALTER TABLE groups ADD CONSTRAINT uq_groups_tenant_id_id UNIQUE USING INDEX uq_groups_tenant_id_id;
ALTER TABLE remediation_campaigns ADD CONSTRAINT uq_remediation_campaigns_tenant_id_id UNIQUE (tenant_id, id);
