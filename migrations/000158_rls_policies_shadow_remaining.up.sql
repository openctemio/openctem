-- RLS policies (shadow mode) — remaining tenant-scoped tables.
--
-- Follows migration 000157 (top 20 tables). Same shape:
--
--   CREATE POLICY <table>_tenant_isolation ON <table>
--   USING ( tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
--         OR current_setting('app.is_platform_admin', true) = 'true' )
--
-- SHADOW MODE — RLS is NOT enabled on these tables. Policies are
-- inert until an ops migration runs ALTER TABLE … ENABLE ROW LEVEL
-- SECURITY per table. See docs/architecture/rls-rollout.md for the
-- procedure.
--
-- Tables without a tenant_id column are auto-skipped by the DO block
-- below — the grep that produced this list caught every table whose
-- DDL references tenant_id, not every tenant-partitioned table, so
-- some entries here (e.g. join tables that only have a tenant_id FK
-- as a composite member) still lack the column and the loop's
-- existence check filters them out.

DO $$
DECLARE
    t TEXT;
    tables TEXT[] := ARRAY[
        'agent_api_keys',
        'agent_audit_logs',
        'agent_metrics',
        'agents',
        'ai_triage_results',
        'api_keys',
        'asset_components',
        'asset_dedup_review',
        'asset_group_members',
        'asset_merge_log',
        'asset_owners',
        'asset_repositories',
        'asset_services',
        'asset_sources',
        'asset_state_history',
        'assignment_rules',
        'attachments',
        'attacker_profiles',
        'attack_path_nodes',
        'attack_paths',
        'attack_simulation_runs',
        'attack_simulations',
        'audit_log_chain',
        'business_service_assets',
        'business_services',
        'business_unit_assets',
        'business_units',
        'commands',
        'compensating_control_assets',
        'compensating_control_findings',
        'compliance_assessments',
        'compliance_controls',
        'compliance_finding_mappings',
        'compliance_frameworks',
        'component_licenses',
        'control_tests',
        'credentials',
        'ctem_cycle_attacker_profiles',
        'ctem_cycle_metrics',
        'ctem_cycle_scope_snapshots',
        'data_sources',
        'email_logs',
        'event_types',
        'exposure_events',
        'exposure_state_history',
        'finding_activities',
        'finding_data_flows',
        'finding_data_sources',
        'finding_flow_locations',
        'finding_group_assignments',
        'finding_regression_events',
        'finding_status_approvals',
        'finding_suppressions',
        'finding_verification_checklists',
        'group_asset_scope_rules',
        'group_members',
        'group_permissions',
        'group_permission_sets',
        'groups',
        'integration_notification_extensions',
        'integrations',
        'integration_scm_extensions',
        'licenses',
        'notification_events',
        'notification_preferences',
        'notification_reads',
        'notifications',
        'notification_state',
        'pentest_campaign_members',
        'pentest_campaigns',
        'pentest_findings',
        'pentest_finding_templates',
        'pentest_reports',
        'pentest_retests',
        'permission_set_items',
        'permission_sets',
        'permission_set_versions',
        'pipeline_runs',
        'pipeline_steps',
        'pipeline_templates',
        'priority_override_rules',
        'registration_tokens',
        'relationship_suggestions',
        'remediation_campaigns',
        'report_schedules',
        'repository_branches',
        'risk_snapshots',
        'role_permissions',
        'roles',
        'rule_bundles',
        'rule_overrides',
        'rules',
        'rule_sources',
        'rule_sync_history',
        'scanner_templates',
        'scan_profiles',
        'scan_profile_template_sources',
        'scan_schedules',
        'scan_sessions',
        'scope_exclusions',
        'scope_targets',
        'sla_policies',
        'step_runs',
        'suppression_rule_audit',
        'suppression_rules',
        'template_sources',
        'tenant_identity_providers',
        'tenant_invitations',
        'tenant_members',
        'tenant_modules',
        'tenants',
        'tenant_tool_configs',
        'threat_actor_cves',
        'threat_actors',
        'tool_categories',
        'tools',
        'user_accessible_assets',
        'user_roles',
        'webhook_deliveries',
        'webhooks',
        'workflow_edges',
        'workflow_node_runs',
        'workflow_nodes',
        'workflow_runs',
        'workflows'
    ];
BEGIN
    FOREACH t IN ARRAY tables
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = t
        ) THEN
            RAISE NOTICE 'rls shadow 158: skipping missing table %', t;
            CONTINUE;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = t
               AND column_name = 'tenant_id'
        ) THEN
            RAISE NOTICE 'rls shadow 158: table % has no tenant_id column; skipped', t;
            CONTINUE;
        END IF;

        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I '
            'USING ( '
            '  tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid '
            '  OR current_setting(''app.is_platform_admin'', true) = ''true'' '
            ')',
            t || '_tenant_isolation', t
        );

        RAISE NOTICE 'rls shadow 158: policy installed on % (RLS not yet enabled)', t;
    END LOOP;
END $$;
