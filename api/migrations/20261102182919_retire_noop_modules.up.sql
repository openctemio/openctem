-- Retire the module switches that did nothing, fold the page-only ones into
-- their parent, and make risk scoring and suppressions always on.
--
-- risk_analysis, sbom_export, tools, scan_profiles and the integrations.*
-- sub-modules gated no route, job or tool. business_impact, crown_jewels,
-- ctem_maturity, executive_summary and mitre_coverage hid a console page only
-- (never its API): the page follows the module of its parent now
-- (business_services, assets, ctem_cycles, reports, threat_intel).
-- risk_scoring (a settings page, while scoring applies to every finding) and
-- suppressions (rules stopped muting when it was off) become core.
-- Idempotent: a second run finds no retired row left.

-- Permissions, event types and asset types filed under a retired module move
-- to its parent.
WITH moved(retired, parent) AS (VALUES
    ('risk_analysis', 'findings'), ('sbom_export', 'components'), ('tools', 'scans'),
    ('scan_profiles', 'scans'), ('business_impact', 'business_services'),
    ('crown_jewels', 'assets'), ('ctem_maturity', 'ctem_cycles'),
    ('executive_summary', 'reports'), ('mitre_coverage', 'threat_intel'),
    ('integrations.scm', 'integrations'), ('integrations.notifications', 'integrations'),
    ('integrations.ticketing', 'integrations'), ('integrations.cloud', 'integrations'),
    ('integrations.siem', 'integrations'), ('integrations.scanners', 'integrations'),
    ('integrations.api', 'integrations'), ('integrations.pipelines', 'integrations'))
UPDATE permissions p SET module_id = m.parent FROM moved m WHERE p.module_id = m.retired;

WITH moved(retired, parent) AS (VALUES
    ('risk_analysis', 'findings'), ('sbom_export', 'components'), ('tools', 'scans'),
    ('scan_profiles', 'scans'), ('business_impact', 'business_services'),
    ('crown_jewels', 'assets'), ('ctem_maturity', 'ctem_cycles'),
    ('executive_summary', 'reports'), ('mitre_coverage', 'threat_intel'),
    ('integrations.scm', 'integrations'), ('integrations.notifications', 'integrations'),
    ('integrations.ticketing', 'integrations'), ('integrations.cloud', 'integrations'),
    ('integrations.siem', 'integrations'), ('integrations.scanners', 'integrations'),
    ('integrations.api', 'integrations'), ('integrations.pipelines', 'integrations'))
UPDATE event_types e SET module_id = m.parent FROM moved m WHERE e.module_id = m.retired;

WITH moved(retired, parent) AS (VALUES
    ('risk_analysis', 'findings'), ('sbom_export', 'components'), ('tools', 'scans'),
    ('scan_profiles', 'scans'), ('business_impact', 'business_services'),
    ('crown_jewels', 'assets'), ('ctem_maturity', 'ctem_cycles'),
    ('executive_summary', 'reports'), ('mitre_coverage', 'threat_intel'),
    ('integrations.scm', 'integrations'), ('integrations.notifications', 'integrations'),
    ('integrations.ticketing', 'integrations'), ('integrations.cloud', 'integrations'),
    ('integrations.siem', 'integrations'), ('integrations.scanners', 'integrations'),
    ('integrations.api', 'integrations'), ('integrations.pipelines', 'integrations'))
UPDATE asset_types a SET module_id = m.parent FROM moved m WHERE a.module_id = m.retired;

-- An organization that switched AI triage off on Settings > Modules keeps it
-- off: the choice moves to its AI settings (the triage use case, mode off)
-- before the module switch is dropped, so nothing turns on silently. The
-- marker lets the down migration give the switch back to exactly these
-- organizations. A settings row that does not exist yet is created with the
-- column defaults (AI stays off until an administrator consents).
INSERT INTO tenant_ai_settings (tenant_id, use_cases)
SELECT tm.tenant_id, jsonb_build_object('triage', jsonb_build_object('mode', 'off', 'from_module_switch', true))
  FROM tenant_modules tm
 WHERE tm.module_id = 'ai_triage' AND NOT tm.is_enabled
ON CONFLICT (tenant_id) DO UPDATE
   SET use_cases = tenant_ai_settings.use_cases || jsonb_build_object('triage',
       COALESCE(tenant_ai_settings.use_cases -> 'triage', '{}'::jsonb)
       || jsonb_build_object('mode', 'off', 'from_module_switch', true));

-- An organization's switch of a module it can no longer switch is dropped
-- (tenant_modules has no ON DELETE): the retired modules, the two modules that
-- are always on now (so their rules and scoring apply again, as the product
-- documents), and the two modules Settings > Modules never listed (the
-- ai_triage switch was carried into the AI settings above).
DELETE FROM tenant_modules WHERE module_id IN (
    'risk_analysis', 'sbom_export', 'tools', 'scan_profiles', 'business_impact',
    'crown_jewels', 'ctem_maturity', 'executive_summary', 'mitre_coverage',
    'risk_scoring', 'suppressions', 'ai_triage', 'branches')
   OR module_id LIKE 'integrations.%';

-- Grants and grace rows of a retired module go with it (ON DELETE CASCADE).
DELETE FROM modules WHERE id IN (
    'risk_analysis', 'sbom_export', 'tools', 'scan_profiles', 'business_impact',
    'crown_jewels', 'ctem_maturity', 'executive_summary', 'mitre_coverage')
   OR parent_module_id = 'integrations' OR id LIKE 'integrations.%';

-- BEGIN module-registry
-- Generated by cmd/gen-modules from configs/modules.yaml. Do not edit by hand.
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status, parent_module_id)
VALUES
    ('dashboard', 'dashboard', 'Dashboard', 'Main dashboard with security overview and statistics', 'LayoutDashboard', 'core', 1, TRUE, true, 'released', NULL),
    ('assets', 'assets', 'Assets', 'The asset inventory, asset groups and every asset type', 'Server', 'core', 2, TRUE, true, 'released', NULL),
    ('findings', 'findings', 'Findings', 'Findings, approvals and exceptions, with SLA deadlines and priority classes', 'AlertTriangle', 'core', 3, TRUE, true, 'released', NULL),
    ('scans', 'scans', 'Scans', 'Scans, Scanning settings (Sensors, Profiles, Tools, Capabilities, Templates, Sources, Secret Store)', 'Search', 'core', 4, TRUE, true, 'released', NULL),
    ('attack_surface', 'attack-surface', 'Attack Surface', 'External attack surface overview — what an adversary sees before touching the network', 'Target', 'scoping', 5, TRUE, false, 'released', NULL),
    ('scope_config', 'scope-config', 'Scope Config', 'CTEM scope — which assets are in scope for prioritisation and reporting', 'Sliders', 'scoping', 6, TRUE, false, 'released', NULL),
    ('business_services', 'business-services', 'Business Services', 'Map business services to the underlying assets that power them', 'Building', 'scoping', 7, TRUE, false, 'released', NULL),
    ('ctem_cycles', 'ctem-cycles', 'CTEM Cycles', 'Gartner CTEM lifecycle — scoping, discovery, prioritisation, validation, mobilisation', 'RotateCcw', 'scoping', 8, TRUE, false, 'released', NULL),
    ('attacker_profiles', 'attacker-profiles', 'Attacker Profiles', 'Threat actor profiles used to drive attack simulation + prioritisation scoring', 'Swords', 'scoping', 9, TRUE, false, 'released', NULL),
    ('credentials', 'credentials', 'Credentials', 'Leaked credentials monitoring and detection', 'Key', 'discovery', 10, TRUE, false, 'released', NULL),
    ('relationships', 'relationships', 'Relationships', 'Asset-to-asset relationships for attack-path modelling', 'Link', 'scoping', 10, TRUE, false, 'released', NULL),
    ('scanner_templates', 'scanner-templates', 'Scanner Templates', 'Catalogue of Nuclei, Betterleaks and Opengrep templates', 'FileCode', 'settings', 10, TRUE, false, 'released', NULL),
    ('business_units', 'business-units', 'Business Units', 'Organisational units that group assets for ownership, criticality and reporting', 'Building2', 'scoping', 11, TRUE, false, 'released', NULL),
    ('components', 'components', 'Components', 'Software Components (SBOM), Ecosystems, Licenses, and vulnerability tracking', 'Package', 'discovery', 11, TRUE, false, 'released', NULL),
    ('template_sources', 'template-sources', 'Rule Sources', 'Git repositories the platform syncs rules and templates from, with snapshots and promotion', 'Database', 'settings', 11, TRUE, false, 'released', NULL),
    ('branches', 'branches', 'Branches', 'Code branches', 'GitBranch', 'discovery', 12, TRUE, false, 'released', NULL),
    ('scan_workflows', 'scan-workflows', 'Scan Workflows', 'Scan workflows: the steps a scan runs, chained by what each step finds', 'GitBranch', 'settings', 12, TRUE, false, 'released', NULL),
    ('threat_model', 'threat-model', 'Threat Model', 'Continuous threat modelling derived from the asset graph and findings', 'Crosshair', 'scoping', 13, TRUE, false, 'released', NULL),
    ('threat_intel', 'threat_intel', 'Threat Intel', 'Threat actors and the threat intelligence workspace', 'Radar', 'prioritization', 20, TRUE, false, 'released', NULL),
    ('exposures', 'exposures', 'Exposures', 'Exposure management and non-CVE security issues', 'ShieldAlert', 'prioritization', 21, TRUE, false, 'released', NULL),
    ('ai_triage', 'ai_triage', 'AI Triage', 'AI triage of findings: verdicts, remediation steps and summaries as suggestions with provenance; risk-lowering changes need a person''s approval', 'Brain', 'prioritization', 22, TRUE, false, 'released', NULL),
    ('sla', 'sla', 'SLA Management', 'SLA policies for remediation time tracking', 'Clock', 'prioritization', 23, TRUE, true, 'released', NULL),
    ('priority_rules', 'priority-rules', 'Priority Rules', 'Declarative priority classification rules (P0..P3)', 'Sliders', 'prioritization', 24, TRUE, false, 'released', NULL),
    ('risk_scoring', 'risk-scoring', 'Risk Scoring', 'Risk scoring config — CVSS / EPSS / KEV / custom weights', 'TrendingUp', 'prioritization', 27, TRUE, true, 'released', NULL),
    ('pentest', 'pentest', 'Penetration Testing', 'Penetration testing campaigns, findings, retests and reports', 'Crosshair', 'validation', 30, TRUE, false, 'released', NULL),
    ('attack_simulation', 'attack-simulation', 'Attack Simulation', 'Breach & Attack Simulation (BAS) — automated adversary emulation to test security controls effectiveness', 'Swords', 'validation', 31, TRUE, false, 'beta', NULL),
    ('control_testing', 'control-testing', 'Control Testing', 'Validate security controls (firewalls, WAF, IDS/IPS) with automated test cases', 'ShieldCheck', 'validation', 32, TRUE, false, 'beta', NULL),
    ('compensating_controls', 'compensating-controls', 'Compensating Controls', 'Controls that reduce finding severity (WAF, EDR, IPS, …)', 'ShieldCheck', 'validation', 33, TRUE, false, 'released', NULL),
    ('remediation', 'remediation', 'Remediation', 'Remediation campaigns that group the fixes for many findings', 'CheckSquare', 'mobilization', 40, TRUE, false, 'released', NULL),
    ('suppressions', 'suppressions', 'Suppressions', 'Finding suppression rules to mute known false positives', 'EyeOff', 'mobilization', 41, TRUE, true, 'released', NULL),
    ('workflows', 'workflows', 'Workflows', 'Trigger-action automation for finding lifecycle (assignment, notification, sync)', 'GitPullRequest', 'mobilization', 43, TRUE, false, 'released', NULL),
    ('reports', 'reports', 'Reports', 'Security reports and analytics', 'FileText', 'insights', 50, TRUE, false, 'released', NULL),
    ('audit', 'audit', 'Audit', 'Audit log for tracking all actions', 'History', 'insights', 51, TRUE, true, 'released', NULL),
    ('integrations', 'integrations', 'Integrations', 'Integrations (SCM, Notifications, CI/CD, Ticketing, SIEM)', 'Plug', 'settings', 60, TRUE, true, 'released', NULL),
    ('sensors', 'sensors', 'Sensors', 'Sensors: scanners, agents and collectors that report to the platform', 'Cpu', 'settings', 61, TRUE, true, 'released', NULL),
    ('team', 'team', 'Team', 'Team members management and invitations', 'Users', 'settings', 62, TRUE, true, 'released', NULL),
    ('groups', 'groups', 'Groups', 'Data scope groups (Teams) for access control', 'UsersCog', 'settings', 63, TRUE, true, 'released', NULL),
    ('roles', 'roles', 'Roles', 'Custom RBAC roles and permission management', 'Shield', 'settings', 64, TRUE, true, 'released', NULL),
    ('settings', 'settings', 'Settings', 'General workspace settings, Risk Scoring, and Module configuration', 'Settings', 'settings', 65, TRUE, true, 'released', NULL),
    ('api_keys', 'api_keys', 'API Keys', 'API key management for programmatic access', 'Key', 'settings', 66, TRUE, true, 'released', NULL),
    ('notification_settings', 'notification_settings', 'Notifications', 'Notification channel settings and delivery configuration', 'Bell', 'settings', 68, TRUE, true, 'released', NULL),
    ('iocs', 'iocs', 'IOCs', 'Indicators of Compromise', 'Fingerprint', 'operations', 84, TRUE, false, 'released', NULL),
    ('compliance', 'compliance', 'Compliance', 'Compliance frameworks, controls and audit-readiness mappings', 'ClipboardCheck', 'compliance', 90, TRUE, false, 'released', NULL)
ON CONFLICT (id) DO UPDATE SET
    slug = EXCLUDED.slug, name = EXCLUDED.name, description = EXCLUDED.description,
    icon = EXCLUDED.icon, category = EXCLUDED.category, display_order = EXCLUDED.display_order,
    is_active = TRUE, is_core = EXCLUDED.is_core, release_status = EXCLUDED.release_status,
    parent_module_id = EXCLUDED.parent_module_id, updated_at = NOW();
-- A row the registry no longer declares is retired: inactive, so no tenant can reach it.
UPDATE modules SET is_active = FALSE, updated_at = NOW()
 WHERE is_active AND id NOT IN ('dashboard', 'assets', 'findings', 'scans', 'attack_surface', 'scope_config', 'business_services', 'ctem_cycles', 'attacker_profiles', 'credentials', 'relationships', 'scanner_templates', 'business_units', 'components', 'template_sources', 'branches', 'scan_workflows', 'threat_model', 'threat_intel', 'exposures', 'ai_triage', 'sla', 'priority_rules', 'risk_scoring', 'pentest', 'attack_simulation', 'control_testing', 'compensating_controls', 'remediation', 'suppressions', 'workflows', 'reports', 'audit', 'integrations', 'sensors', 'team', 'groups', 'roles', 'settings', 'api_keys', 'notification_settings', 'iocs', 'compliance');
-- END module-registry
