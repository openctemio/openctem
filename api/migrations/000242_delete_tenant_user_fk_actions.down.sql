-- Reverts 000242: the FKs go back to ON DELETE NO ACTION (deleting a tenant
-- or user with such rows fails again), the three requester/uploader columns
-- become NOT NULL again and the asset_state_history triggers return to their
-- 000169 form.
--
-- Rows whose requester/uploader was deleted while 000242 was applied have a
-- NULL there and cannot satisfy NOT NULL; the revert stops instead of
-- deleting or inventing data. Resolve those rows by hand, then run it again.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM attachments WHERE uploaded_by IS NULL)
       OR EXISTS (SELECT 1 FROM finding_status_approvals WHERE requested_by IS NULL)
       OR EXISTS (SELECT 1 FROM suppression_rules WHERE requested_by IS NULL) THEN
        RAISE EXCEPTION '000242 down: attachments.uploaded_by, finding_status_approvals.requested_by or suppression_rules.requested_by holds NULL (their user was deleted); cannot restore NOT NULL';
    END IF;
END $$;

ALTER TABLE compliance_assessments
    DROP CONSTRAINT compliance_assessments_tenant_id_fkey,
    ADD CONSTRAINT compliance_assessments_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE compliance_finding_mappings
    DROP CONSTRAINT compliance_finding_mappings_tenant_id_fkey,
    ADD CONSTRAINT compliance_finding_mappings_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE compliance_frameworks
    DROP CONSTRAINT compliance_frameworks_tenant_id_fkey,
    ADD CONSTRAINT compliance_frameworks_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE group_asset_scope_rules
    DROP CONSTRAINT group_asset_scope_rules_tenant_id_fkey,
    ADD CONSTRAINT group_asset_scope_rules_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE pentest_campaign_members
    DROP CONSTRAINT pentest_campaign_members_tenant_id_fkey,
    ADD CONSTRAINT pentest_campaign_members_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE pentest_campaigns
    DROP CONSTRAINT pentest_campaigns_tenant_id_fkey,
    ADD CONSTRAINT pentest_campaigns_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE pentest_finding_templates
    DROP CONSTRAINT pentest_finding_templates_tenant_id_fkey,
    ADD CONSTRAINT pentest_finding_templates_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE pentest_findings
    DROP CONSTRAINT pentest_findings_tenant_id_fkey,
    ADD CONSTRAINT pentest_findings_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE pentest_reports
    DROP CONSTRAINT pentest_reports_tenant_id_fkey,
    ADD CONSTRAINT pentest_reports_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE pentest_retests
    DROP CONSTRAINT pentest_retests_tenant_id_fkey,
    ADD CONSTRAINT pentest_retests_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE ingest_jobs DROP CONSTRAINT ingest_jobs_tenant_id_fkey;
ALTER TABLE asset_owners
    DROP CONSTRAINT asset_owners_assigned_by_fkey,
    ADD CONSTRAINT asset_owners_assigned_by_fkey
        FOREIGN KEY (assigned_by) REFERENCES users(id);
ALTER TABLE attachments
    DROP CONSTRAINT attachments_uploaded_by_fkey,
    ADD CONSTRAINT attachments_uploaded_by_fkey
        FOREIGN KEY (uploaded_by) REFERENCES users(id);
ALTER TABLE compliance_assessments
    DROP CONSTRAINT compliance_assessments_assessed_by_fkey,
    ADD CONSTRAINT compliance_assessments_assessed_by_fkey
        FOREIGN KEY (assessed_by) REFERENCES users(id);
ALTER TABLE compliance_finding_mappings
    DROP CONSTRAINT compliance_finding_mappings_created_by_fkey,
    ADD CONSTRAINT compliance_finding_mappings_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id);
ALTER TABLE finding_status_approvals
    DROP CONSTRAINT finding_status_approvals_approved_by_fkey,
    ADD CONSTRAINT finding_status_approvals_approved_by_fkey
        FOREIGN KEY (approved_by) REFERENCES users(id),
    DROP CONSTRAINT finding_status_approvals_rejected_by_fkey,
    ADD CONSTRAINT finding_status_approvals_rejected_by_fkey
        FOREIGN KEY (rejected_by) REFERENCES users(id),
    DROP CONSTRAINT finding_status_approvals_requested_by_fkey,
    ADD CONSTRAINT finding_status_approvals_requested_by_fkey
        FOREIGN KEY (requested_by) REFERENCES users(id);
ALTER TABLE group_members
    DROP CONSTRAINT group_members_added_by_fkey,
    ADD CONSTRAINT group_members_added_by_fkey
        FOREIGN KEY (added_by) REFERENCES users(id);
ALTER TABLE pentest_campaign_members
    DROP CONSTRAINT pentest_campaign_members_added_by_fkey,
    ADD CONSTRAINT pentest_campaign_members_added_by_fkey
        FOREIGN KEY (added_by) REFERENCES users(id);
ALTER TABLE pentest_campaigns
    DROP CONSTRAINT pentest_campaigns_created_by_fkey,
    ADD CONSTRAINT pentest_campaigns_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id),
    DROP CONSTRAINT pentest_campaigns_lead_user_id_fkey,
    ADD CONSTRAINT pentest_campaigns_lead_user_id_fkey
        FOREIGN KEY (lead_user_id) REFERENCES users(id);
ALTER TABLE pentest_finding_templates
    DROP CONSTRAINT pentest_finding_templates_created_by_fkey,
    ADD CONSTRAINT pentest_finding_templates_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id);
ALTER TABLE pentest_findings
    DROP CONSTRAINT pentest_findings_assigned_to_fkey,
    ADD CONSTRAINT pentest_findings_assigned_to_fkey
        FOREIGN KEY (assigned_to) REFERENCES users(id),
    DROP CONSTRAINT pentest_findings_created_by_fkey,
    ADD CONSTRAINT pentest_findings_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id),
    DROP CONSTRAINT pentest_findings_reviewed_by_fkey,
    ADD CONSTRAINT pentest_findings_reviewed_by_fkey
        FOREIGN KEY (reviewed_by) REFERENCES users(id);
ALTER TABLE pentest_reports
    DROP CONSTRAINT pentest_reports_created_by_fkey,
    ADD CONSTRAINT pentest_reports_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id);
ALTER TABLE pentest_retests
    DROP CONSTRAINT pentest_retests_tested_by_fkey,
    ADD CONSTRAINT pentest_retests_tested_by_fkey
        FOREIGN KEY (tested_by) REFERENCES users(id);
ALTER TABLE relationship_suggestions
    DROP CONSTRAINT relationship_suggestions_reviewed_by_fkey,
    ADD CONSTRAINT relationship_suggestions_reviewed_by_fkey
        FOREIGN KEY (reviewed_by) REFERENCES users(id);
ALTER TABLE suppression_rule_audit
    DROP CONSTRAINT suppression_rule_audit_actor_id_fkey,
    ADD CONSTRAINT suppression_rule_audit_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES users(id);
ALTER TABLE suppression_rules
    DROP CONSTRAINT suppression_rules_approved_by_fkey,
    ADD CONSTRAINT suppression_rules_approved_by_fkey
        FOREIGN KEY (approved_by) REFERENCES users(id),
    DROP CONSTRAINT suppression_rules_rejected_by_fkey,
    ADD CONSTRAINT suppression_rules_rejected_by_fkey
        FOREIGN KEY (rejected_by) REFERENCES users(id),
    DROP CONSTRAINT suppression_rules_requested_by_fkey,
    ADD CONSTRAINT suppression_rules_requested_by_fkey
        FOREIGN KEY (requested_by) REFERENCES users(id);
ALTER TABLE tenant_identity_providers
    DROP CONSTRAINT tenant_identity_providers_created_by_fkey,
    ADD CONSTRAINT tenant_identity_providers_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id);

ALTER TABLE attachments ALTER COLUMN uploaded_by SET NOT NULL;
ALTER TABLE finding_status_approvals ALTER COLUMN requested_by SET NOT NULL;
ALTER TABLE suppression_rules ALTER COLUMN requested_by SET NOT NULL;

CREATE OR REPLACE FUNCTION prevent_audit_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'UPDATE on asset_state_history is not allowed. Audit records are immutable. Insert a new record instead.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_recent_audit_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.changed_at > NOW() - INTERVAL '30 days'
       AND EXISTS (SELECT 1 FROM assets WHERE id = OLD.asset_id) THEN
        RAISE EXCEPTION 'Cannot delete asset_state_history records less than 30 days old (changed_at: %). Use retention jobs for cleanup.', OLD.changed_at;
        RETURN NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
