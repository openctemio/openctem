-- =============================================================================
-- Migration 005: Permissions
-- OpenCTEM OSS Edition
--
-- Permission IDs follow the hierarchical convention:
--   {module}:{subfeature}:{action}   (e.g., assets:groups:read)
--   {module}:{action}                (e.g., dashboard:read)
--
-- These IDs MUST match the Go constants in pkg/domain/permission/permission.go
-- and the frontend constants in ui/src/lib/permissions/constants.ts
-- =============================================================================

-- Permissions (Granular actions within modules)
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(100) PRIMARY KEY,
    module_id VARCHAR(50) REFERENCES modules(id) ON DELETE SET NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE permissions IS 'Granular permissions for actions within modules';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_permissions_module ON permissions(module_id);
CREATE INDEX IF NOT EXISTS idx_permissions_active ON permissions(is_active) WHERE is_active = true;

-- =============================================================================
-- Seed Permissions
-- =============================================================================

INSERT INTO permissions (id, module_id, name, description) VALUES
    -- =========================================================================
    -- CORE MODULES
    -- =========================================================================

    -- Dashboard
    ('dashboard:read', 'dashboard', 'View Dashboard', 'View main dashboard'),

    -- Audit
    ('audit:read', 'audit', 'View Audit Logs', 'See audit history'),

    -- Settings
    ('settings:read', 'settings', 'View Settings', 'See workspace configuration'),
    ('settings:write', 'settings', 'Update Settings', 'Modify settings'),

    -- =========================================================================
    -- ASSETS MODULE (assets:*)
    -- =========================================================================

    -- Asset permissions (top-level)
    ('assets:read', 'assets', 'View Assets', 'View asset details and list'),
    ('assets:write', 'assets', 'Manage Assets', 'Create and update assets'),
    ('assets:delete', 'assets', 'Delete Assets', 'Remove assets permanently'),
    ('assets:import', 'assets', 'Import Assets', 'Import assets from external sources'),
    ('assets:export', 'assets', 'Export Assets', 'Export asset data'),

    -- Asset Groups (assets:groups:*)
    ('assets:groups:read', 'assets', 'View Asset Groups', 'View asset groups'),
    ('assets:groups:write', 'assets', 'Manage Asset Groups', 'Create and update asset groups'),
    ('assets:groups:delete', 'assets', 'Delete Asset Groups', 'Remove asset groups'),

    -- Components (assets:components:*)
    ('assets:components:read', 'components', 'View Components', 'View software components'),
    ('assets:components:write', 'components', 'Manage Components', 'Update component info'),
    ('assets:components:delete', 'components', 'Delete Components', 'Remove components'),

    -- =========================================================================
    -- FINDINGS MODULE (findings:*)
    -- =========================================================================

    -- Finding permissions (top-level)
    ('findings:read', 'findings', 'View Findings', 'View security findings'),
    ('findings:write', 'findings', 'Update Findings', 'Modify finding details'),
    ('findings:delete', 'findings', 'Delete Findings', 'Remove findings'),
    ('findings:assign', 'findings', 'Assign Findings', 'Assign findings to users/groups'),
    ('findings:triage', 'findings', 'Triage Findings', 'Triage and categorize findings'),
    ('findings:status', 'findings', 'Change Status', 'Update finding status'),
    ('findings:export', 'findings', 'Export Findings', 'Export findings data'),
    ('findings:bulk_update', 'findings', 'Bulk Update', 'Update multiple findings at once'),

    -- Suppressions (findings:suppressions:*)
    ('findings:suppressions:read', 'findings', 'View Suppression Rules', 'View suppression rules'),
    ('findings:suppressions:write', 'findings', 'Manage Suppression Rules', 'Create and update rules'),
    ('findings:suppressions:delete', 'findings', 'Delete Suppression Rules', 'Remove suppression rules'),
    ('findings:suppressions:approve', 'findings', 'Approve Suppressions', 'Approve suppression requests'),

    -- Vulnerabilities (findings:vulnerabilities:*)
    ('findings:vulnerabilities:read', 'vulnerabilities', 'View Vulnerabilities', 'View vulnerability database'),
    ('findings:vulnerabilities:write', 'vulnerabilities', 'Manage Vulnerabilities', 'Update vulnerability info'),
    ('findings:vulnerabilities:delete', 'vulnerabilities', 'Delete Vulnerabilities', 'Remove vulnerabilities'),

    -- Credentials (findings:credentials:*)
    ('findings:credentials:read', 'credentials', 'View Credentials', 'View leaked credentials'),
    ('findings:credentials:write', 'credentials', 'Manage Credentials', 'Update credential records'),

    -- Remediation (findings:remediation:*)
    ('findings:remediation:read', 'remediation', 'View Remediation', 'View remediation tasks'),
    ('findings:remediation:write', 'remediation', 'Manage Remediation', 'Create and update tasks'),

    -- Workflows (findings:workflows:*)
    ('findings:workflows:read', 'remediation', 'View Workflows', 'View automation workflows'),
    ('findings:workflows:write', 'remediation', 'Manage Workflows', 'Create and update workflows'),

    -- Policies (findings:policies:*)
    ('findings:policies:read', 'policies', 'View Policies', 'View security policies'),
    ('findings:policies:write', 'policies', 'Manage Policies', 'Create and update policies'),
    ('findings:policies:delete', 'policies', 'Delete Policies', 'Remove policies'),

    -- Exposures (findings:exposures:*)
    ('findings:exposures:read', 'exposures', 'View Exposures', 'View security exposures'),
    ('findings:exposures:write', 'exposures', 'Manage Exposures', 'Update exposure status'),
    ('findings:exposures:delete', 'exposures', 'Delete Exposures', 'Remove exposure records'),
    ('findings:exposures:triage', 'exposures', 'Triage Exposures', 'Triage and categorize exposures'),

    -- =========================================================================
    -- SCANS MODULE (scans:*)
    -- =========================================================================

    -- Scan permissions (top-level)
    ('scans:read', 'scans', 'View Scans', 'View scan history and results'),
    ('scans:write', 'scans', 'Manage Scans', 'Configure scan settings'),
    ('scans:delete', 'scans', 'Delete Scans', 'Remove scan history'),
    ('scans:execute', 'scans', 'Execute Scans', 'Trigger new scans'),

    -- Scan Profiles (scans:profiles:*)
    ('scans:profiles:read', 'scan_profiles', 'View Scan Profiles', 'View scan profiles'),
    ('scans:profiles:write', 'scan_profiles', 'Manage Scan Profiles', 'Create and update scan profiles'),
    ('scans:profiles:delete', 'scan_profiles', 'Delete Scan Profiles', 'Remove scan profiles'),

    -- Sources (scans:sources:*)
    ('scans:sources:read', 'sources', 'View Sources', 'View data sources'),
    ('scans:sources:write', 'sources', 'Manage Sources', 'Configure data sources'),
    ('scans:sources:delete', 'sources', 'Delete Sources', 'Remove data sources'),

    -- Tools (scans:tools:*)
    ('scans:tools:read', 'scans', 'View Tools', 'View available tools'),
    ('scans:tools:write', 'scans', 'Manage Tools', 'Configure tool settings'),
    ('scans:tools:delete', 'scans', 'Delete Tools', 'Remove tools'),

    -- Tenant Tools (scans:tenant_tools:*)
    ('scans:tenant_tools:read', 'scans', 'View Tool Configs', 'View tenant tool configurations'),
    ('scans:tenant_tools:write', 'scans', 'Manage Tool Configs', 'Configure tenant tools'),
    ('scans:tenant_tools:delete', 'scans', 'Delete Tool Configs', 'Remove tenant tool configs'),

    -- Scanner Templates (scans:templates:*)
    ('scans:templates:read', 'scans', 'View Scanner Templates', 'View scanner templates'),
    ('scans:templates:write', 'scans', 'Manage Scanner Templates', 'Create and update templates'),
    ('scans:templates:delete', 'scans', 'Delete Scanner Templates', 'Remove scanner templates'),

    -- Secret Store (scans:secret_store:*)
    ('scans:secret_store:read', 'secrets', 'View Secret Store', 'View secret store'),
    ('scans:secret_store:write', 'secrets', 'Manage Secret Store', 'Create and update secrets'),
    ('scans:secret_store:delete', 'secrets', 'Delete Secrets', 'Remove secrets'),

    -- =========================================================================
    -- AGENTS MODULE (agents:*)
    -- =========================================================================

    -- Agent permissions (top-level)
    ('agents:read', 'agents', 'View Agents', 'View scan agents'),
    ('agents:write', 'agents', 'Manage Agents', 'Configure agents'),
    ('agents:delete', 'agents', 'Delete Agents', 'Remove agents'),

    -- Commands (agents:commands:*)
    ('agents:commands:read', 'agents', 'View Commands', 'View agent commands'),
    ('agents:commands:write', 'agents', 'Send Commands', 'Send commands to agents'),
    ('agents:commands:delete', 'agents', 'Delete Commands', 'Remove agent commands'),

    -- =========================================================================
    -- TEAM MODULE (team:*)
    -- =========================================================================

    -- Team settings (top-level)
    ('team:read', 'team', 'View Team Settings', 'See team configuration'),
    ('team:update', 'team', 'Update Team', 'Modify team settings'),
    ('team:delete', 'team', 'Delete Team', 'Remove team permanently'),

    -- Members (team:members:*)
    ('team:members:read', 'team', 'View Members', 'See team members'),
    ('team:members:invite', 'team', 'Invite Members', 'Send invitations'),
    ('team:members:write', 'team', 'Manage Members', 'Change roles, remove members'),

    -- Groups (team:groups:*)
    ('team:groups:read', 'groups', 'View Groups', 'See groups list'),
    ('team:groups:write', 'groups', 'Manage Groups', 'Create and edit groups'),
    ('team:groups:delete', 'groups', 'Delete Groups', 'Remove groups'),
    ('team:groups:members', 'groups', 'Manage Group Members', 'Add/remove group members'),
    ('team:groups:assets', 'groups', 'Manage Group Assets', 'Assign assets to groups'),

    -- Roles (team:roles:*)
    ('team:roles:read', 'roles', 'View Roles', 'See available roles'),
    ('team:roles:write', 'roles', 'Manage Roles', 'Create and edit custom roles'),
    ('team:roles:delete', 'roles', 'Delete Roles', 'Remove custom roles'),
    ('team:roles:assign', 'roles', 'Assign Roles', 'Assign roles to users'),

    -- Permission Sets (team:permission_sets:*)
    ('team:permission_sets:read', 'roles', 'View Permission Sets', 'View permission sets'),
    ('team:permission_sets:write', 'roles', 'Manage Permission Sets', 'Create and edit permission sets'),
    ('team:permission_sets:delete', 'roles', 'Delete Permission Sets', 'Remove permission sets'),

    -- Assignment Rules (team:assignment_rules:*)
    ('team:assignment_rules:read', 'roles', 'View Assignment Rules', 'View assignment rules'),
    ('team:assignment_rules:write', 'roles', 'Manage Assignment Rules', 'Create and edit rules'),
    ('team:assignment_rules:delete', 'roles', 'Delete Assignment Rules', 'Remove assignment rules'),

    -- =========================================================================
    -- INTEGRATIONS MODULE (integrations:*)
    -- =========================================================================

    -- Integration permissions (top-level)
    ('integrations:read', 'integrations', 'View Integrations', 'View external integrations'),
    ('integrations:manage', 'integrations', 'Manage Integrations', 'Configure integrations'),

    -- SCM Connections (integrations:scm:*)
    ('integrations:scm:read', 'integrations', 'View SCM Connections', 'View SCM integrations'),
    ('integrations:scm:write', 'integrations', 'Manage SCM Connections', 'Configure SCM integrations'),
    ('integrations:scm:delete', 'integrations', 'Delete SCM Connections', 'Remove SCM integrations'),

    -- Notifications (integrations:notifications:*)
    ('integrations:notifications:read', 'integrations', 'View Notifications', 'View notification settings'),
    ('integrations:notifications:write', 'integrations', 'Manage Notifications', 'Configure notifications'),
    ('integrations:notifications:delete', 'integrations', 'Delete Notifications', 'Remove notifications'),

    -- Webhooks (integrations:webhooks:*)
    ('integrations:webhooks:read', 'integrations', 'View Webhooks', 'View webhook configurations'),
    ('integrations:webhooks:write', 'integrations', 'Manage Webhooks', 'Configure webhooks'),
    ('integrations:webhooks:delete', 'integrations', 'Delete Webhooks', 'Remove webhooks'),

    -- API Keys (integrations:api_keys:*)
    ('integrations:api_keys:read', 'integrations', 'View API Keys', 'View API key list'),
    ('integrations:api_keys:write', 'integrations', 'Manage API Keys', 'Create and update API keys'),
    ('integrations:api_keys:delete', 'integrations', 'Delete API Keys', 'Revoke API keys'),

    -- Pipelines (integrations:pipelines:*)
    ('integrations:pipelines:read', 'integrations', 'View Pipelines', 'View pipeline configurations'),
    ('integrations:pipelines:write', 'integrations', 'Manage Pipelines', 'Create and update pipelines'),
    ('integrations:pipelines:delete', 'integrations', 'Delete Pipelines', 'Remove pipelines'),
    ('integrations:pipelines:execute', 'integrations', 'Execute Pipelines', 'Trigger pipeline runs'),

    -- =========================================================================
    -- SETTINGS MODULE (settings:*)
    -- =========================================================================

    -- Billing (settings:billing:*)
    ('settings:billing:read', 'settings', 'View Billing', 'View billing information'),
    ('settings:billing:write', 'settings', 'Manage Billing', 'Manage billing and subscriptions'),

    -- SLA (settings:sla:*)
    ('settings:sla:read', 'sla', 'View SLA', 'View SLA policies and status'),
    ('settings:sla:write', 'sla', 'Manage SLA', 'Create and update SLA policies'),
    ('settings:sla:delete', 'sla', 'Delete SLA', 'Remove SLA policies'),

    -- =========================================================================
    -- ATTACK SURFACE MODULE (attack_surface:*)
    -- =========================================================================

    -- Scope (attack_surface:scope:*)
    ('attack_surface:scope:read', 'scope', 'View Scope', 'View scope configuration'),
    ('attack_surface:scope:write', 'scope', 'Manage Scope', 'Configure scope rules'),
    ('attack_surface:scope:delete', 'scope', 'Delete Scope', 'Remove scope rules'),

    -- =========================================================================
    -- VALIDATION MODULE (validation:*)
    -- =========================================================================

    ('validation:read', 'pentest', 'View Validation', 'View penetration testing'),
    ('validation:write', 'pentest', 'Manage Validation', 'Configure pentest settings'),

    -- =========================================================================
    -- REPORTS MODULE (reports:*)
    -- =========================================================================

    ('reports:read', 'reports', 'View Reports', 'View reports and analytics'),
    ('reports:write', 'reports', 'Create Reports', 'Generate custom reports'),

    -- =========================================================================
    -- THREAT INTELLIGENCE (threat_intel:*)
    -- =========================================================================

    ('threat_intel:read', 'threat_intel', 'View Threat Intel', 'View threat intelligence'),
    ('threat_intel:write', 'threat_intel', 'Manage Threat Intel', 'Configure threat intel sources'),

    -- AI Triage
    ('ai_triage:read', 'ai_triage', 'View AI Triage', 'View AI triage results'),
    ('ai_triage:trigger', 'ai_triage', 'Trigger AI Triage', 'Run AI triage on findings')

ON CONFLICT (id) DO UPDATE SET
    module_id = EXCLUDED.module_id,
    name = EXCLUDED.name,
    description = EXCLUDED.description;
