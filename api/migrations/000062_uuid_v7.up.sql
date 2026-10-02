-- =============================================================================
-- Migration 062: UUID v7 Support
-- =============================================================================
-- Adds uuid_generate_v7() function for time-sortable UUIDs.
-- UUID v7 embeds Unix timestamp (ms precision) in the first 48 bits,
-- providing natural chronological ordering and better B-tree index locality.
--
-- Note: Existing UUID v4 data remains fully compatible — no data migration needed.
-- This only affects DEFAULT values for new rows inserted via raw SQL.
-- The Go application generates IDs before INSERT, so this is mainly for
-- consistency if any manual SQL inserts are performed.
-- =============================================================================

-- Ensure pgcrypto extension is available (needed for gen_random_bytes)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create UUID v7 generation function (RFC 9562)
CREATE OR REPLACE FUNCTION uuid_generate_v7() RETURNS uuid AS $$
DECLARE
    unix_ts_ms BIGINT;
    buffer BYTEA;
BEGIN
    unix_ts_ms = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;
    -- Start with 16 zero bytes
    buffer = E'\\x00000000000000000000000000000000'::bytea;
    -- Set timestamp (first 6 bytes = 48 bits)
    -- Must mask BEFORE casting to int to avoid integer overflow
    buffer = set_byte(buffer, 0, ((unix_ts_ms >> 40) & 255)::int);
    buffer = set_byte(buffer, 1, ((unix_ts_ms >> 32) & 255)::int);
    buffer = set_byte(buffer, 2, ((unix_ts_ms >> 24) & 255)::int);
    buffer = set_byte(buffer, 3, ((unix_ts_ms >> 16) & 255)::int);
    buffer = set_byte(buffer, 4, ((unix_ts_ms >> 8) & 255)::int);
    buffer = set_byte(buffer, 5, (unix_ts_ms & 255)::int);
    -- Fill remaining 10 bytes with random data
    buffer = overlay(buffer PLACING gen_random_bytes(10) FROM 7);
    -- Set version to 7 (bits 48-51 = 0111)
    buffer = set_byte(buffer, 6, (get_byte(buffer, 6) & 15) | (7 << 4));
    -- Set variant to RFC 4122 (bits 64-65 = 10)
    buffer = set_byte(buffer, 8, (get_byte(buffer, 8) & 63) | 128);
    RETURN encode(buffer, 'hex')::uuid;
END
$$ LANGUAGE plpgsql VOLATILE;

COMMENT ON FUNCTION uuid_generate_v7 IS 'Generates RFC 9562 UUID v7 (time-sortable, ms precision timestamp + random)';

-- =============================================================================
-- Update table defaults to use UUID v7
-- =============================================================================
-- Generated from actual database schema (92 tables with UUID id columns).

-- Users & Auth
ALTER TABLE users ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE sessions ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE refresh_tokens ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE registration_tokens ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Tenants & Members
ALTER TABLE tenants ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE tenant_members ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE tenant_invitations ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- RBAC
ALTER TABLE roles ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE role_permissions ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE user_roles ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Groups
ALTER TABLE groups ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Assets
ALTER TABLE assets ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_services ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_relationships ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_components ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_groups ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_owners ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_state_history ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_types ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE asset_type_categories ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Components
ALTER TABLE components ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Vulnerabilities
ALTER TABLE vulnerabilities ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Findings
ALTER TABLE findings ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_activities ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_comments ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_data_flows ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_data_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_flow_locations ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_source_categories ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE finding_suppressions ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Exposures
ALTER TABLE exposures ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE exposure_events ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE exposure_state_history ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Data Sources
ALTER TABLE data_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Tools
ALTER TABLE tools ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE tool_executions ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE tool_categories ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE tenant_tool_configs ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Agents
ALTER TABLE agents ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE agent_api_keys ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE agent_audit_logs ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE agent_metrics ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE commands ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Scans
ALTER TABLE scans ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE scan_sessions ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE scan_profiles ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE scan_schedules ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE scan_profile_template_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Scanner Templates
ALTER TABLE scanner_templates ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE template_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Pipelines
ALTER TABLE pipeline_templates ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE pipeline_steps ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE pipeline_runs ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE step_runs ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Integrations
ALTER TABLE integrations ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Notifications
ALTER TABLE notification_outbox ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE notification_events ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Audit Logs
ALTER TABLE audit_logs ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Credentials
ALTER TABLE credentials ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Suppression Rules
ALTER TABLE suppression_rules ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE suppression_rule_audit ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Threat Intelligence
ALTER TABLE threat_intel_sync_status ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Rule Management
ALTER TABLE rules ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE rule_bundles ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE rule_overrides ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE rule_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE rule_sync_history ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Scope Configuration
ALTER TABLE scope_targets ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE scope_exclusions ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Capabilities
ALTER TABLE capabilities ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Attack Paths
ALTER TABLE attack_paths ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE attack_path_nodes ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Workflows
ALTER TABLE workflows ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE workflow_nodes ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE workflow_edges ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE workflow_runs ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE workflow_node_runs ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Permission Sets
ALTER TABLE permission_sets ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- SLA & AI
ALTER TABLE sla_policies ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE ai_triage_results ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Admin
ALTER TABLE admin_users ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE admin_audit_logs ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- API Keys & Webhooks
ALTER TABLE api_keys ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE webhooks ALTER COLUMN id SET DEFAULT uuid_generate_v7();
ALTER TABLE webhook_deliveries ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Settings
ALTER TABLE settings ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Email
ALTER TABLE email_logs ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Assignment Rules
ALTER TABLE assignment_rules ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Target Asset Type Mappings
ALTER TABLE target_asset_type_mappings ALTER COLUMN id SET DEFAULT uuid_generate_v7();

-- Repository Branches
ALTER TABLE repository_branches ALTER COLUMN id SET DEFAULT uuid_generate_v7();
