-- Deleting an organization or a user failed on foreign keys that neither
-- cascade nor null out (NO ACTION), e.g. pentest_campaigns_tenant_id_fkey
-- blocked DELETE /api/v1/tenants/{tenant} and
-- suppression_rules_requested_by_fkey blocked deleting a person.
--
--   * Rows a tenant owns          -> ON DELETE CASCADE.
--   * "Who did it" user columns   -> ON DELETE SET NULL. The row stays, the
--     actor becomes unknown. Three such columns were NOT NULL
--     (suppression_rules.requested_by, finding_status_approvals.requested_by,
--     attachments.uploaded_by); they become nullable, because keeping them
--     NOT NULL + RESTRICT would mean a user who once filed a suppression
--     request, an approval request or an evidence file could never be deleted.
--   * asset_state_history is immutable by trigger: its BEFORE UPDATE trigger
--     also rejected the SET NULL that deleting a user performs, and its BEFORE
--     DELETE trigger only knew about the asset-delete cascade. Both now admit
--     exactly the referential actions and keep refusing direct edits.
--
-- internal/infra/postgres/tenant_user_delete_db_test.go enumerates every FK
-- to tenants/users from pg_constraint and fails on a new blocking one.

-- ---------------------------------------------------------------------------
-- Tenant-owned rows: CASCADE
-- ---------------------------------------------------------------------------
ALTER TABLE compliance_assessments
    DROP CONSTRAINT compliance_assessments_tenant_id_fkey,
    ADD CONSTRAINT compliance_assessments_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE compliance_finding_mappings
    DROP CONSTRAINT compliance_finding_mappings_tenant_id_fkey,
    ADD CONSTRAINT compliance_finding_mappings_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
-- compliance_frameworks.tenant_id is NULL for the built-in frameworks; only
-- a tenant's custom frameworks go with it.
ALTER TABLE compliance_frameworks
    DROP CONSTRAINT compliance_frameworks_tenant_id_fkey,
    ADD CONSTRAINT compliance_frameworks_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE group_asset_scope_rules
    DROP CONSTRAINT group_asset_scope_rules_tenant_id_fkey,
    ADD CONSTRAINT group_asset_scope_rules_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE pentest_campaign_members
    DROP CONSTRAINT pentest_campaign_members_tenant_id_fkey,
    ADD CONSTRAINT pentest_campaign_members_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE pentest_campaigns
    DROP CONSTRAINT pentest_campaigns_tenant_id_fkey,
    ADD CONSTRAINT pentest_campaigns_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
-- NULL tenant_id = a built-in template, unaffected.
ALTER TABLE pentest_finding_templates
    DROP CONSTRAINT pentest_finding_templates_tenant_id_fkey,
    ADD CONSTRAINT pentest_finding_templates_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE pentest_findings
    DROP CONSTRAINT pentest_findings_tenant_id_fkey,
    ADD CONSTRAINT pentest_findings_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE pentest_reports
    DROP CONSTRAINT pentest_reports_tenant_id_fkey,
    ADD CONSTRAINT pentest_reports_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE pentest_retests
    DROP CONSTRAINT pentest_retests_tenant_id_fkey,
    ADD CONSTRAINT pentest_retests_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- ingest_jobs had no tenant FK at all; only v2 jobs reach the tenant through
-- ingest_reports. A v1 job (raw report payload) outlived its tenant and the
-- worker kept retrying it. NOT VALID: rows already orphaned by an earlier
-- tenant delete would fail validation; the cascade works without it.
ALTER TABLE ingest_jobs
    ADD CONSTRAINT ingest_jobs_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE NOT VALID;

-- ---------------------------------------------------------------------------
-- "Who did it" user references: SET NULL
-- ---------------------------------------------------------------------------
ALTER TABLE attachments ALTER COLUMN uploaded_by DROP NOT NULL;
ALTER TABLE finding_status_approvals ALTER COLUMN requested_by DROP NOT NULL;
ALTER TABLE suppression_rules ALTER COLUMN requested_by DROP NOT NULL;

ALTER TABLE asset_owners
    DROP CONSTRAINT asset_owners_assigned_by_fkey,
    ADD CONSTRAINT asset_owners_assigned_by_fkey
        FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE attachments
    DROP CONSTRAINT attachments_uploaded_by_fkey,
    ADD CONSTRAINT attachments_uploaded_by_fkey
        FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE compliance_assessments
    DROP CONSTRAINT compliance_assessments_assessed_by_fkey,
    ADD CONSTRAINT compliance_assessments_assessed_by_fkey
        FOREIGN KEY (assessed_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE compliance_finding_mappings
    DROP CONSTRAINT compliance_finding_mappings_created_by_fkey,
    ADD CONSTRAINT compliance_finding_mappings_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE finding_status_approvals
    DROP CONSTRAINT finding_status_approvals_approved_by_fkey,
    ADD CONSTRAINT finding_status_approvals_approved_by_fkey
        FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT finding_status_approvals_rejected_by_fkey,
    ADD CONSTRAINT finding_status_approvals_rejected_by_fkey
        FOREIGN KEY (rejected_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT finding_status_approvals_requested_by_fkey,
    ADD CONSTRAINT finding_status_approvals_requested_by_fkey
        FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE group_members
    DROP CONSTRAINT group_members_added_by_fkey,
    ADD CONSTRAINT group_members_added_by_fkey
        FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE pentest_campaign_members
    DROP CONSTRAINT pentest_campaign_members_added_by_fkey,
    ADD CONSTRAINT pentest_campaign_members_added_by_fkey
        FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE pentest_campaigns
    DROP CONSTRAINT pentest_campaigns_created_by_fkey,
    ADD CONSTRAINT pentest_campaigns_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT pentest_campaigns_lead_user_id_fkey,
    ADD CONSTRAINT pentest_campaigns_lead_user_id_fkey
        FOREIGN KEY (lead_user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE pentest_finding_templates
    DROP CONSTRAINT pentest_finding_templates_created_by_fkey,
    ADD CONSTRAINT pentest_finding_templates_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE pentest_findings
    DROP CONSTRAINT pentest_findings_assigned_to_fkey,
    ADD CONSTRAINT pentest_findings_assigned_to_fkey
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT pentest_findings_created_by_fkey,
    ADD CONSTRAINT pentest_findings_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT pentest_findings_reviewed_by_fkey,
    ADD CONSTRAINT pentest_findings_reviewed_by_fkey
        FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE pentest_reports
    DROP CONSTRAINT pentest_reports_created_by_fkey,
    ADD CONSTRAINT pentest_reports_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE pentest_retests
    DROP CONSTRAINT pentest_retests_tested_by_fkey,
    ADD CONSTRAINT pentest_retests_tested_by_fkey
        FOREIGN KEY (tested_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE relationship_suggestions
    DROP CONSTRAINT relationship_suggestions_reviewed_by_fkey,
    ADD CONSTRAINT relationship_suggestions_reviewed_by_fkey
        FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL;
-- Audit trail: keep the entry, lose only the actor.
ALTER TABLE suppression_rule_audit
    DROP CONSTRAINT suppression_rule_audit_actor_id_fkey,
    ADD CONSTRAINT suppression_rule_audit_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE suppression_rules
    DROP CONSTRAINT suppression_rules_approved_by_fkey,
    ADD CONSTRAINT suppression_rules_approved_by_fkey
        FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT suppression_rules_rejected_by_fkey,
    ADD CONSTRAINT suppression_rules_rejected_by_fkey
        FOREIGN KEY (rejected_by) REFERENCES users(id) ON DELETE SET NULL,
    DROP CONSTRAINT suppression_rules_requested_by_fkey,
    ADD CONSTRAINT suppression_rules_requested_by_fkey
        FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE tenant_identity_providers
    DROP CONSTRAINT tenant_identity_providers_created_by_fkey,
    ADD CONSTRAINT tenant_identity_providers_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- asset_state_history audit triggers
-- ---------------------------------------------------------------------------

-- Immutable, except for the one change deleting a user makes: the
-- asset_state_history_changed_by_fkey SET NULL. That is recognised by its
-- shape (changed_by goes to NULL, nothing else changes) and by the user row
-- really being gone, so a direct "UPDATE ... SET changed_by = NULL" while the
-- user exists is still refused.
CREATE OR REPLACE FUNCTION prevent_audit_update()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.changed_by IS NOT NULL
       AND NEW.changed_by IS NULL
       AND (to_jsonb(NEW) - 'changed_by') = (to_jsonb(OLD) - 'changed_by')
       AND NOT EXISTS (SELECT 1 FROM users WHERE id = OLD.changed_by) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'UPDATE on asset_state_history is not allowed. Audit records are immutable. Insert a new record instead.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Recent rows (< 30 days) may only go with their parent: the asset
-- (migration 000169) or, now, the whole tenant. Both are recognised by the
-- parent row already being gone, which is the case while the FK cascade runs
-- and never for a direct DELETE, so this does not depend on the order in
-- which Postgres walks the cascade. A session flag or pg_trigger_depth()
-- would instead also unlock deletes issued from any other trigger.
CREATE OR REPLACE FUNCTION prevent_recent_audit_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.changed_at > NOW() - INTERVAL '30 days'
       AND EXISTS (SELECT 1 FROM assets WHERE id = OLD.asset_id)
       AND EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        RAISE EXCEPTION 'Cannot delete asset_state_history records less than 30 days old (changed_at: %). Use retention jobs for cleanup.', OLD.changed_at;
        RETURN NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
