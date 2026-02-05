-- =============================================================================
-- Migration 004: Modules (Feature Registry for UI)
-- OpenCTEM OSS Edition
--
-- Modules represent features in the platform. In OSS edition, all modules are
-- available by default. This table is used for:
-- 1. UI sidebar navigation structure
-- 2. Feature metadata (icons, categories, display order)
-- 3. Release status tracking (released, coming_soon, beta)
-- =============================================================================

-- Modules (Feature registry)
CREATE TABLE IF NOT EXISTS modules (
    id VARCHAR(50) PRIMARY KEY,
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    category VARCHAR(50) NOT NULL DEFAULT 'core',
    display_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    release_status VARCHAR(20) DEFAULT 'released',
    parent_module_id VARCHAR(50) REFERENCES modules(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_modules_release_status CHECK (release_status IN ('released', 'coming_soon', 'beta', 'deprecated', 'disabled'))
);

COMMENT ON TABLE modules IS 'Feature registry for UI navigation (OSS: all modules enabled)';
COMMENT ON COLUMN modules.category IS 'UI grouping: core, discovery, prioritization, validation, mobilization, insights, settings';
COMMENT ON COLUMN modules.release_status IS 'Feature maturity: released, coming_soon, beta, deprecated, disabled';
COMMENT ON COLUMN modules.parent_module_id IS 'Parent module for sub-modules (e.g., assets.domains)';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_modules_slug ON modules(slug);
CREATE INDEX IF NOT EXISTS idx_modules_category ON modules(category);
CREATE INDEX IF NOT EXISTS idx_modules_display_order ON modules(display_order);
CREATE INDEX IF NOT EXISTS idx_modules_release_status ON modules(release_status);
CREATE INDEX IF NOT EXISTS idx_modules_parent ON modules(parent_module_id);
CREATE INDEX IF NOT EXISTS idx_modules_active ON modules(is_active) WHERE is_active = true;

-- =============================================================================
-- Seed Core Modules
-- =============================================================================

INSERT INTO modules (id, slug, name, description, icon, category, display_order, release_status) VALUES
    -- Core modules
    ('dashboard', 'dashboard', 'Dashboard', 'Main dashboard with security overview', 'LayoutDashboard', 'core', 1, 'released'),
    ('assets', 'assets', 'Assets', 'Asset inventory management', 'Server', 'core', 2, 'released'),
    ('findings', 'findings', 'Findings', 'Security findings and vulnerabilities', 'AlertTriangle', 'core', 3, 'released'),
    ('scans', 'scans', 'Scans', 'Security scanning', 'Search', 'core', 4, 'released'),

    -- Discovery modules
    ('credentials', 'credentials', 'Credentials', 'Leaked credentials monitoring', 'Key', 'discovery', 10, 'released'),
    ('components', 'components', 'Components', 'Software components and SBOM', 'Package', 'discovery', 11, 'released'),
    ('branches', 'branches', 'Branches', 'Code branches', 'GitBranch', 'discovery', 12, 'released'),
    ('vulnerabilities', 'vulnerabilities', 'Vulnerabilities', 'Vulnerability database', 'ShieldAlert', 'discovery', 13, 'released'),

    -- Prioritization modules
    ('threat_intel', 'threat_intel', 'Threat Intel', 'Threat intelligence and IOCs', 'Radar', 'prioritization', 20, 'released'),
    ('exposures', 'exposures', 'Exposures', 'Exposure management and tracking', 'ShieldAlert', 'prioritization', 21, 'released'),
    ('ai_triage', 'ai_triage', 'AI Triage', 'AI-powered vulnerability triage', 'Brain', 'prioritization', 22, 'released'),
    ('sla', 'sla', 'SLA Management', 'Service level agreements and compliance', 'Clock', 'prioritization', 23, 'released'),

    -- Validation modules
    ('pentest', 'pentest', 'Penetration Testing', 'Penetration testing campaigns', 'Crosshair', 'validation', 30, 'released'),

    -- Mobilization modules
    ('remediation', 'remediation', 'Remediation', 'Remediation tasks and workflows', 'CheckSquare', 'mobilization', 40, 'released'),
    ('suppressions', 'suppressions', 'Suppressions', 'Finding suppression rules', 'EyeOff', 'mobilization', 41, 'released'),
    ('policies', 'policies', 'Policies', 'Security policies', 'FileText', 'mobilization', 42, 'released'),

    -- Insights modules
    ('reports', 'reports', 'Reports', 'Reports and analytics', 'FileText', 'insights', 50, 'released'),
    ('audit', 'audit', 'Audit', 'Audit logs', 'History', 'insights', 51, 'released'),

    -- Settings modules
    ('integrations', 'integrations', 'Integrations', 'External integrations', 'Plug', 'settings', 60, 'released'),
    ('agents', 'agents', 'Agents', 'Security agents', 'Cpu', 'settings', 61, 'released'),
    ('team', 'team', 'Team', 'Team member management', 'Users', 'settings', 62, 'released'),
    ('groups', 'groups', 'Groups', 'Data scope groups', 'UsersCog', 'settings', 63, 'released'),
    ('roles', 'roles', 'Roles', 'Custom RBAC roles', 'Shield', 'settings', 64, 'released'),
    ('settings', 'settings', 'Settings', 'Workspace settings', 'Settings', 'settings', 65, 'released'),
    ('api_keys', 'api_keys', 'API Keys', 'API key management', 'Key', 'settings', 66, 'released'),
    ('webhooks', 'webhooks', 'Webhooks', 'Webhook configurations', 'Webhook', 'settings', 67, 'released'),
    ('notification_settings', 'notification_settings', 'Notifications', 'Notification settings', 'Bell', 'settings', 68, 'released'),

    -- Data modules
    ('sources', 'sources', 'Sources', 'Finding and data sources', 'Database', 'data', 70, 'released'),
    ('secrets', 'secrets', 'Secrets', 'Secret management', 'Lock', 'data', 71, 'released'),
    ('scope', 'scope', 'Scope', 'Scope configuration', 'Target', 'data', 72, 'released'),

    -- Operations modules
    ('pipelines', 'pipelines', 'Pipelines', 'Scan pipelines', 'GitPullRequest', 'operations', 80, 'released'),
    ('tools', 'tools', 'Tools', 'Security tools', 'Wrench', 'operations', 81, 'released'),
    ('commands', 'commands', 'Commands', 'Agent commands', 'Terminal', 'operations', 82, 'released'),
    ('scan_profiles', 'scan_profiles', 'Scan Profiles', 'Scan configuration profiles', 'Sliders', 'operations', 83, 'released'),
    ('iocs', 'iocs', 'IOCs', 'Indicators of Compromise', 'Fingerprint', 'operations', 84, 'released')
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    category = EXCLUDED.category,
    display_order = EXCLUDED.display_order,
    release_status = EXCLUDED.release_status,
    updated_at = NOW();

-- =============================================================================
-- Seed Sub-modules
-- =============================================================================

INSERT INTO modules (id, slug, name, description, icon, category, display_order, parent_module_id, release_status) VALUES
    -- Assets sub-modules (Infrastructure)
    ('assets.domains', 'domains', 'Domains', 'Domain and subdomain management', 'Globe', 'discovery', 1, 'assets', 'released'),
    ('assets.subdomains', 'subdomains', 'Subdomains', 'Subdomain discovery and management', 'Globe', 'discovery', 2, 'assets', 'released'),
    ('assets.ips', 'ips', 'IP Addresses', 'IP address management', 'Server', 'discovery', 3, 'assets', 'released'),
    ('assets.ports', 'ports', 'Ports', 'Network port management', 'Plug', 'discovery', 4, 'assets', 'released'),
    ('assets.networks', 'networks', 'Networks', 'Network segment management', 'Network', 'discovery', 5, 'assets', 'released'),

    -- Assets sub-modules (Applications)
    ('assets.websites', 'websites', 'Websites', 'Web application management', 'Globe', 'discovery', 10, 'assets', 'released'),
    ('assets.apis', 'apis', 'APIs', 'API endpoint management', 'Zap', 'discovery', 11, 'assets', 'released'),
    ('assets.web_apps', 'web_apps', 'Web Applications', 'Web application management', 'Layout', 'discovery', 12, 'assets', 'released'),
    ('assets.mobile_apps', 'mobile_apps', 'Mobile Apps', 'Mobile application management', 'Smartphone', 'discovery', 13, 'assets', 'released'),
    ('assets.services', 'services', 'Services', 'Running service management', 'Activity', 'discovery', 14, 'assets', 'released'),

    -- Assets sub-modules (Code & Repositories)
    ('assets.repositories', 'repositories', 'Repositories', 'Source code repository management', 'GitBranch', 'discovery', 20, 'assets', 'released'),
    ('assets.artifacts', 'artifacts', 'Artifacts', 'Build artifact management', 'Package', 'discovery', 21, 'assets', 'released'),
    ('assets.containers', 'containers', 'Container Images', 'Container image management', 'Box', 'discovery', 22, 'assets', 'released'),

    -- Assets sub-modules (Cloud)
    ('assets.cloud_accounts', 'cloud_accounts', 'Cloud Accounts', 'Cloud provider account management', 'Cloud', 'discovery', 30, 'assets', 'released'),
    ('assets.cloud_resources', 'cloud_resources', 'Cloud Resources', 'Cloud resource management', 'Cloud', 'discovery', 31, 'assets', 'released'),
    ('assets.kubernetes', 'kubernetes', 'Kubernetes', 'Kubernetes cluster management', 'Box', 'discovery', 32, 'assets', 'released'),
    ('assets.serverless', 'serverless', 'Serverless', 'Serverless function management', 'Zap', 'discovery', 33, 'assets', 'released'),

    -- Assets sub-modules (Data)
    ('assets.databases', 'databases', 'Databases', 'Database management', 'Database', 'discovery', 40, 'assets', 'released'),
    ('assets.data_stores', 'data_stores', 'Data Stores', 'Data storage management', 'HardDrive', 'discovery', 41, 'assets', 'released'),

    -- Assets sub-modules (Identity)
    ('assets.certificates', 'certificates', 'Certificates', 'SSL/TLS certificate management', 'Shield', 'discovery', 50, 'assets', 'released'),
    ('assets.credentials', 'credentials_assets', 'Credentials', 'Credential and secret management', 'Key', 'discovery', 51, 'assets', 'released'),

    -- Assets sub-modules (Other)
    ('assets.hosts', 'hosts', 'Hosts', 'Host management', 'Server', 'discovery', 60, 'assets', 'released'),
    ('assets.iot', 'iot', 'IoT Devices', 'IoT device management', 'Cpu', 'discovery', 61, 'assets', 'released'),
    ('assets.hardware', 'hardware', 'Hardware', 'Physical hardware management', 'HardDrive', 'discovery', 62, 'assets', 'released'),

    -- Integrations sub-modules
    ('integrations.scm', 'scm', 'SCM Integrations', 'Source code management integrations', 'GitBranch', 'settings', 1, 'integrations', 'released'),
    ('integrations.notifications', 'notifications', 'Notification Channels', 'Notification channel integrations', 'Bell', 'settings', 2, 'integrations', 'released'),
    ('integrations.ticketing', 'ticketing', 'Ticketing', 'Issue tracking integrations', 'Ticket', 'settings', 3, 'integrations', 'released'),
    ('integrations.cloud', 'cloud', 'Cloud Providers', 'Cloud provider integrations', 'Cloud', 'settings', 4, 'integrations', 'released'),
    ('integrations.siem', 'siem', 'SIEM', 'SIEM integrations', 'Shield', 'settings', 5, 'integrations', 'released'),
    ('integrations.scanners', 'scanners', 'Scanners', 'External scanner integrations', 'Search', 'settings', 6, 'integrations', 'released'),
    ('integrations.webhooks', 'webhooks_int', 'Webhooks', 'Webhook integrations', 'Webhook', 'settings', 7, 'integrations', 'released'),
    ('integrations.api', 'api_int', 'API Integrations', 'API integrations', 'Zap', 'settings', 8, 'integrations', 'released'),
    ('integrations.pipelines', 'pipelines_int', 'Pipeline Integrations', 'CI/CD pipeline integrations', 'GitPullRequest', 'settings', 9, 'integrations', 'released'),

    -- AI Triage sub-modules
    ('ai_triage.bulk', 'ai_triage_bulk', 'Bulk Triage', 'Bulk triage operations', 'Layers', 'prioritization', 1, 'ai_triage', 'released'),
    ('ai_triage.auto', 'ai_triage_auto', 'Auto Triage', 'Auto-triage on finding creation', 'Zap', 'prioritization', 2, 'ai_triage', 'released'),
    ('ai_triage.workflow', 'ai_triage_workflow', 'Workflow Triage', 'Workflow triggers and actions', 'GitPullRequest', 'prioritization', 3, 'ai_triage', 'released'),
    ('ai_triage.byok', 'ai_triage_byok', 'BYOK Mode', 'Bring Your Own Key mode', 'Key', 'prioritization', 4, 'ai_triage', 'released'),
    ('ai_triage.agent', 'ai_triage_agent', 'Agent Mode', 'Self-hosted Agent mode', 'Cpu', 'prioritization', 5, 'ai_triage', 'released'),
    ('ai_triage.custom_prompts', 'ai_triage_custom_prompts', 'Custom Prompts', 'Custom prompt templates', 'FileText', 'prioritization', 6, 'ai_triage', 'released')
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    category = EXCLUDED.category,
    display_order = EXCLUDED.display_order,
    parent_module_id = EXCLUDED.parent_module_id,
    release_status = EXCLUDED.release_status,
    updated_at = NOW();

-- =============================================================================
-- Enterprise Modules (Deactivated in OSS Edition)
-- These modules are included for data completeness but disabled by default.
-- They can be activated for enterprise deployments.
-- =============================================================================

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, release_status) VALUES
    ('billing', 'billing', 'Billing', 'Billing and payment management', 'CreditCard', 'platform', 100, false, 'released'),
    ('subscription', 'subscription', 'Subscription', 'Subscription and plan management', 'Receipt', 'platform', 101, false, 'released'),
    ('platform', 'platform', 'Platform Admin', 'Platform administration and multi-tenancy', 'Building', 'platform', 102, false, 'released'),
    ('licensing', 'licensing', 'Licensing', 'License management and activation', 'Key', 'platform', 103, false, 'released'),
    ('usage', 'usage', 'Usage Analytics', 'Usage tracking and analytics', 'BarChart', 'platform', 104, false, 'released')
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    category = EXCLUDED.category,
    display_order = EXCLUDED.display_order,
    is_active = EXCLUDED.is_active,
    release_status = EXCLUDED.release_status,
    updated_at = NOW();

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_modules_updated_at ON modules;
CREATE TRIGGER trigger_modules_updated_at
    BEFORE UPDATE ON modules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
