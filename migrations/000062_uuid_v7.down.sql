-- =============================================================================
-- Migration 062: UUID v7 Support (Rollback)
-- =============================================================================
-- Reverts table defaults back to gen_random_uuid() (UUID v4)
-- and drops the uuid_generate_v7() function.
-- Note: Existing UUID v7 data remains valid — no data changes needed.
-- =============================================================================

-- Users & Auth
ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE sessions ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE refresh_tokens ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE registration_tokens ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Tenants & Members
ALTER TABLE tenants ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE tenant_members ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE tenant_invitations ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- RBAC
ALTER TABLE roles ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE role_permissions ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE user_roles ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Groups
ALTER TABLE groups ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Assets
ALTER TABLE assets ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_services ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_relationships ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_components ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_groups ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_owners ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_state_history ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_types ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE asset_type_categories ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Components
ALTER TABLE components ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Vulnerabilities
ALTER TABLE vulnerabilities ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Findings
ALTER TABLE findings ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_activities ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_comments ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_data_flows ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_data_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_flow_locations ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_source_categories ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE finding_suppressions ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Exposures
ALTER TABLE exposures ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE exposure_events ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE exposure_state_history ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Data Sources
ALTER TABLE data_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Tools
ALTER TABLE tools ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE tool_executions ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE tool_categories ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE tenant_tool_configs ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Agents
ALTER TABLE agents ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE agent_api_keys ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE agent_audit_logs ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE agent_metrics ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE commands ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Scans
ALTER TABLE scans ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE scan_sessions ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE scan_profiles ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE scan_schedules ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE scan_profile_template_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Scanner Templates
ALTER TABLE scanner_templates ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE template_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Pipelines
ALTER TABLE pipeline_templates ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE pipeline_steps ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE pipeline_runs ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE step_runs ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Integrations
ALTER TABLE integrations ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Notifications
ALTER TABLE notification_outbox ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE notification_events ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Audit Logs
ALTER TABLE audit_logs ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Credentials
ALTER TABLE credentials ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Suppression Rules
ALTER TABLE suppression_rules ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE suppression_rule_audit ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Threat Intelligence
ALTER TABLE threat_intel_sync_status ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Rule Management
ALTER TABLE rules ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE rule_bundles ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE rule_overrides ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE rule_sources ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE rule_sync_history ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Scope Configuration
ALTER TABLE scope_targets ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE scope_exclusions ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Capabilities
ALTER TABLE capabilities ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Attack Paths
ALTER TABLE attack_paths ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE attack_path_nodes ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Workflows
ALTER TABLE workflows ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE workflow_nodes ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE workflow_edges ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE workflow_runs ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE workflow_node_runs ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Permission Sets
ALTER TABLE permission_sets ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- SLA & AI
ALTER TABLE sla_policies ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE ai_triage_results ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Admin
ALTER TABLE admin_users ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE admin_audit_logs ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- API Keys & Webhooks
ALTER TABLE api_keys ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE webhooks ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE webhook_deliveries ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Settings
ALTER TABLE settings ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Email
ALTER TABLE email_logs ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Assignment Rules
ALTER TABLE assignment_rules ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Target Asset Type Mappings
ALTER TABLE target_asset_type_mappings ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Repository Branches
ALTER TABLE repository_branches ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Drop UUID v7 function
DROP FUNCTION IF EXISTS uuid_generate_v7();
