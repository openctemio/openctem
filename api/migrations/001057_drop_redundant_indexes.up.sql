-- Drop redundant indexes (legacy cleanup, wave 2).
--
-- Each index below is fully covered by another index on the same table that
-- stays: either an exact duplicate (often a plain index created next to the
-- UNIQUE constraint on the same column), or a left prefix of a wider btree
-- index with the same predicate. Any query the dropped index served can use
-- the covering one. Fewer indexes means cheaper writes and less to vacuum.
--
-- Never dropped here: an index that backs a constraint (primary key, unique
-- constraint, or the unique index a foreign key references), and indexes on
-- tables that a later cleanup migration drops as a whole.
--
-- 117 indexes. Plain DROP INDEX: every table is small, the lock is brief.

DROP INDEX IF EXISTS public.idx_admin_users_email; -- covered by uq_admin_email
DROP INDEX IF EXISTS public.idx_admin_users_prefix; -- covered by uq_admin_api_key_prefix
DROP INDEX IF EXISTS public.idx_ai_triage_budgets_tenant_period; -- covered by ai_triage_budgets_tenant_id_period_start_key
DROP INDEX IF EXISTS public.idx_ai_triage_finding; -- covered by idx_ai_triage_finding_latest
DROP INDEX IF EXISTS public.idx_api_keys_hash; -- covered by api_keys_key_hash_key
DROP INDEX IF EXISTS public.idx_api_keys_tenant; -- covered by unique_api_key_name
DROP INDEX IF EXISTS public.idx_approvals_finding; -- covered by idx_approvals_finding_status
DROP INDEX IF EXISTS public.idx_approvals_tenant_status; -- covered by idx_approvals_tenant_status_created
DROP INDEX IF EXISTS public.idx_asset_components_asset; -- covered by idx_asset_components_depth
DROP INDEX IF EXISTS public.idx_asset_components_tenant; -- covered by idx_asset_components_tenant_asset
DROP INDEX IF EXISTS public.idx_asset_dedup_review_tenant; -- covered by idx_asset_dedup_review_status
DROP INDEX IF EXISTS public.idx_asset_group_members_group_id; -- covered by asset_group_members_pkey
DROP INDEX IF EXISTS public.idx_asset_groups_tenant_id; -- covered by unique_asset_group_name
DROP INDEX IF EXISTS public.idx_asset_merge_log_tenant; -- covered by idx_asset_merge_log_created
DROP INDEX IF EXISTS public.idx_asset_owners_group; -- covered by idx_asset_owners_group_asset
DROP INDEX IF EXISTS public.idx_asset_rel_source; -- covered by uq_asset_relationship
DROP INDEX IF EXISTS public.idx_asset_relationships_tenant_type; -- covered by idx_asset_rel_type
DROP INDEX IF EXISTS public.idx_asset_services_asset; -- covered by unique_asset_service
DROP INDEX IF EXISTS public.idx_asset_services_tenant; -- covered by idx_asset_services_tenant_type
DROP INDEX IF EXISTS public.idx_asset_sources_asset; -- covered by asset_sources_unique
DROP INDEX IF EXISTS public.idx_asset_sources_primary; -- covered by idx_asset_sources_asset_primary
DROP INDEX IF EXISTS public.idx_asset_state_history_asset; -- covered by idx_asset_state_history_asset_time
DROP INDEX IF EXISTS public.idx_asset_state_history_tenant; -- covered by idx_asset_state_history_tenant_time
DROP INDEX IF EXISTS public.idx_asset_type_categories_code; -- covered by asset_type_categories_code_key
DROP INDEX IF EXISTS public.idx_asset_types_code; -- covered by asset_types_code_key
DROP INDEX IF EXISTS public.idx_assets_pii; -- covered by idx_assets_critical_pii
DROP INDEX IF EXISTS public.idx_assets_tenant_id_pk; -- covered by uq_assets_tenant_id_id
DROP INDEX IF EXISTS public.idx_assets_tenant_name; -- covered by idx_assets_name_tenant_unique
DROP INDEX IF EXISTS public.idx_assets_tenant_type; -- covered by idx_assets_tenant_type_crit_status
DROP INDEX IF EXISTS public.idx_assignment_rules_tenant; -- covered by idx_assignment_rules_priority
DROP INDEX IF EXISTS public.idx_attack_path_nodes_path_id; -- covered by idx_attack_path_nodes_order
DROP INDEX IF EXISTS public.idx_attack_simulations_tenant; -- covered by idx_attack_simulations_mitre
DROP INDEX IF EXISTS public.idx_business_service_assets_service; -- covered by business_service_assets_service_id_asset_id_dependency_type_key
DROP INDEX IF EXISTS public.idx_business_services_tenant; -- covered by idx_business_services_criticality
DROP INDEX IF EXISTS public.idx_business_units_tenant; -- covered by business_units_tenant_id_name_key
DROP INDEX IF EXISTS public.idx_campaign_tickets_campaign; -- covered by uq_campaign_ticket_provider
DROP INDEX IF EXISTS public.idx_capabilities_tenant; -- covered by capabilities_tenant_id_name_key
DROP INDEX IF EXISTS public.idx_comment_reactions_comment_id; -- covered by comment_reactions_unique
DROP INDEX IF EXISTS public.idx_compliance_assessments_tenant; -- covered by idx_compliance_assessments_framework
DROP INDEX IF EXISTS public.idx_compliance_controls_framework; -- covered by idx_compliance_controls_unique
DROP INDEX IF EXISTS public.idx_compliance_finding_mappings_tenant; -- covered by idx_compliance_finding_mappings_unique
DROP INDEX IF EXISTS public.idx_component_licenses_component; -- covered by pk_component_licenses
DROP INDEX IF EXISTS public.idx_components_purl; -- covered by uq_components_purl
DROP INDEX IF EXISTS public.idx_control_tests_tenant; -- covered by idx_control_tests_framework
DROP INDEX IF EXISTS public.idx_credentials_tenant; -- covered by credentials_name_unique
DROP INDEX IF EXISTS public.idx_data_flows_finding; -- covered by uq_finding_data_flow
DROP INDEX IF EXISTS public.idx_exposure_events_tenant; -- covered by uq_exposure_events_fingerprint
DROP INDEX IF EXISTS public.idx_exposures_tenant_id; -- covered by idx_exposures_tenant_severity
DROP INDEX IF EXISTS public.idx_fbo_finding; -- covered by uq_finding_branch
DROP INDEX IF EXISTS public.idx_fga_finding; -- covered by finding_group_assignments_finding_id_group_id_key
DROP INDEX IF EXISTS public.idx_finding_activities_tenant; -- covered by idx_finding_activities_tenant_created
DROP INDEX IF EXISTS public.idx_finding_activities_tenant_id; -- covered by idx_finding_activities_tenant_created
DROP INDEX IF EXISTS public.idx_finding_source_categories_code; -- covered by finding_source_categories_code_key
DROP INDEX IF EXISTS public.idx_finding_sources_code; -- covered by finding_sources_code_key
DROP INDEX IF EXISTS public.idx_finding_suppressions_finding; -- covered by finding_suppressions_unique
DROP INDEX IF EXISTS public.idx_findings_tenant_asset; -- covered by idx_findings_tenant_asset_status
DROP INDEX IF EXISTS public.idx_flow_locations_file; -- covered by idx_flow_locations_file_line
DROP INDEX IF EXISTS public.idx_group_members_user; -- covered by idx_group_members_user_group
DROP INDEX IF EXISTS public.idx_groups_tenant; -- covered by groups_tenant_id_slug_key
DROP INDEX IF EXISTS public.idx_integrations_tenant_id; -- covered by integrations_name_unique
DROP INDEX IF EXISTS public.idx_licenses_spdx; -- covered by uq_licenses_spdx_id
DROP INDEX IF EXISTS public.idx_modules_parent_module_id; -- covered by idx_modules_parent_active_order
DROP INDEX IF EXISTS public.idx_modules_slug; -- covered by modules_slug_key
DROP INDEX IF EXISTS public.idx_pentest_campaigns_tenant; -- covered by idx_pentest_campaigns_priority
DROP INDEX IF EXISTS public.idx_pentest_findings_tenant; -- covered by idx_pentest_findings_severity
DROP INDEX IF EXISTS public.idx_pipeline_runs_status; -- covered by idx_pipeline_runs_tenant_status_created
DROP INDEX IF EXISTS public.idx_pipeline_steps_pipeline; -- covered by pipeline_steps_key_unique
DROP INDEX IF EXISTS public.idx_pipeline_templates_tenant; -- covered by pipeline_templates_name_version_unique
DROP INDEX IF EXISTS public.idx_refresh_tokens_token_hash; -- covered by refresh_tokens_token_hash_key
DROP INDEX IF EXISTS public.idx_remediation_campaigns_tenant; -- covered by idx_remediation_campaigns_priority
DROP INDEX IF EXISTS public.idx_report_schedules_tenant; -- covered by idx_report_schedules_active
DROP INDEX IF EXISTS public.idx_repository_branches_repository_id; -- covered by unique_repository_branch
DROP INDEX IF EXISTS public.idx_risk_snapshots_range; -- covered by risk_snapshots_tenant_id_snapshot_date_key
DROP INDEX IF EXISTS public.idx_role_permissions_role; -- covered by role_permissions_unique
DROP INDEX IF EXISTS public.idx_roles_tenant; -- covered by roles_slug_unique
DROP INDEX IF EXISTS public.idx_scan_profiles_tenant_id; -- covered by scan_profiles_name_unique
DROP INDEX IF EXISTS public.idx_scan_sessions_tenant; -- covered by idx_scan_sessions_asset_value
DROP INDEX IF EXISTS public.idx_scanner_templates_tenant; -- covered by unique_scanner_template
DROP INDEX IF EXISTS public.idx_scans_tenant; -- covered by scans_tenant_name_unique
DROP INDEX IF EXISTS public.idx_scans_tenant_status; -- covered by idx_scans_tenant_status_schedule
DROP INDEX IF EXISTS public.idx_scim_groups_tenant; -- covered by uq_scim_groups_tenant_name
DROP INDEX IF EXISTS public.idx_scope_exclusions_tenant; -- covered by unique_scope_exclusion
DROP INDEX IF EXISTS public.idx_scope_rules_group; -- covered by idx_scope_rules_group_tenant
DROP INDEX IF EXISTS public.idx_scope_rules_group_tenant_active; -- covered by idx_scope_rules_group_tenant_active_priority
DROP INDEX IF EXISTS public.idx_scope_rules_tenant; -- covered by idx_scope_rules_tenant_active
DROP INDEX IF EXISTS public.idx_scope_targets_tenant; -- covered by unique_scope_target
DROP INDEX IF EXISTS public.idx_scope_targets_type; -- covered by unique_scope_target
DROP INDEX IF EXISTS public.idx_sensors_tenant_id; -- covered by uq_sensors_tenant_id_id
DROP INDEX IF EXISTS public.idx_sensors_tenant_id_pk; -- covered by uq_sensors_tenant_id_id
DROP INDEX IF EXISTS public.idx_settings_tenant; -- covered by unique_setting_key
DROP INDEX IF EXISTS public.idx_simulation_runs_tenant; -- covered by idx_simulation_runs_status
DROP INDEX IF EXISTS public.idx_step_runs_pipeline_run; -- covered by idx_step_runs_order
DROP INDEX IF EXISTS public.idx_suppression_rules_tenant; -- covered by idx_suppression_rules_tenant_id_pk
DROP INDEX IF EXISTS public.idx_template_sources_tenant; -- covered by unique_template_source_name
DROP INDEX IF EXISTS public.idx_tenant_invitations_token; -- covered by tenant_invitations_token_key
DROP INDEX IF EXISTS public.idx_tenant_members_tenant_id; -- covered by idx_tenant_members_tenant_status
DROP INDEX IF EXISTS public.idx_tenant_members_user_id; -- covered by tenant_members_user_tenant_unique
DROP INDEX IF EXISTS public.idx_tenant_modules_tenant; -- covered by tenant_modules_tenant_id_module_id_key
DROP INDEX IF EXISTS public.idx_tenant_tool_configs_tenant; -- covered by tenant_tool_configs_unique
DROP INDEX IF EXISTS public.idx_tenants_slug; -- covered by tenants_slug_key
DROP INDEX IF EXISTS public.idx_threat_actors_tenant; -- covered by idx_threat_actors_active
DROP INDEX IF EXISTS public.idx_threat_intel_sync_source; -- covered by threat_intel_sync_status_source_name_key
DROP INDEX IF EXISTS public.idx_threat_models_tenant; -- covered by uq_threat_models_scope
DROP INDEX IF EXISTS public.idx_tip_tenant_id; -- covered by uq_tenant_provider
DROP INDEX IF EXISTS public.idx_tool_executions_tenant; -- covered by idx_tool_executions_tenant_tool
DROP INDEX IF EXISTS public.idx_tools_tenant; -- covered by tools_tenant_name_unique
DROP INDEX IF EXISTS public.idx_user_accessible_assets_user; -- covered by uq_user_accessible_assets
DROP INDEX IF EXISTS public.idx_user_dashboards_tenant_user; -- covered by uq_user_dashboards_tenant_user_name
DROP INDEX IF EXISTS public.idx_user_roles_user_tenant; -- covered by user_roles_unique
DROP INDEX IF EXISTS public.idx_users_email; -- covered by users_email_key
DROP INDEX IF EXISTS public.idx_verification_checklist_finding; -- covered by finding_verification_checklists_finding_id_key
DROP INDEX IF EXISTS public.idx_vulnerabilities_cve_id; -- covered by vulnerabilities_cve_id_key
DROP INDEX IF EXISTS public.idx_webhooks_tenant; -- covered by unique_webhook_name
DROP INDEX IF EXISTS public.idx_workflow_edges_workflow; -- covered by idx_uq_workflow_edge
DROP INDEX IF EXISTS public.idx_workflow_node_runs_run; -- covered by idx_uq_workflow_node_run
DROP INDEX IF EXISTS public.idx_workflow_nodes_workflow; -- covered by uq_workflow_node_key
DROP INDEX IF EXISTS public.idx_workflows_tenant; -- covered by uq_workflow_name
