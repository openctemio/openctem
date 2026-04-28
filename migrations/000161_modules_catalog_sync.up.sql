-- =============================================================================
-- Migration 000161: Sync modules catalog with shipped features
--
-- The sidebar ships features (attack_surface, scope_config, ctem_cycles,
-- attacker_profiles, workflows, compensating_controls, priority_rules,
-- business_services, business_impact, risk_analysis, ctem_maturity,
-- executive_summary, mitre_coverage, sbom_export, scanner_templates,
-- template_sources, scan_pipelines, remediation_tasks, relationships)
-- that were never registered in the modules table. Tenant admins cannot
-- enable/disable them because the toggle UI iterates the modules row set.
--
-- This migration back-fills those rows so the Settings > Modules screen
-- shows every shipped feature. Existing rows are left alone via
-- ON CONFLICT DO NOTHING — operators who already customised descriptions
-- or display_order are not overwritten.
--
-- The companion Go file pkg/domain/module/dependency.go encodes the
-- platform-wide static dependency graph (e.g. ai_triage requires
-- findings). See CLAUDE.md §9 for the rationale behind putting graph in
-- code rather than a DB table.
-- =============================================================================

BEGIN;

-- Scoping cluster ----------------------------------------------------------

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('attack_surface',     'attack-surface',     'Attack Surface',     'External attack surface overview — what an adversary sees before touching the network', 'Target',       'scoping', 5,  true, false, 'released'),
    ('scope_config',       'scope-config',       'Scope Config',       'CTEM scope — which assets are in scope for prioritisation and reporting',                 'Sliders',      'scoping', 6,  true, false, 'released'),
    ('business_services',  'business-services',  'Business Services',  'Map business services to the underlying assets that power them',                         'Building',     'scoping', 7,  true, false, 'released'),
    ('ctem_cycles',        'ctem-cycles',        'CTEM Cycles',        'Gartner CTEM lifecycle — scoping, discovery, prioritisation, validation, mobilisation',  'RotateCcw',    'scoping', 8,  true, false, 'released'),
    ('attacker_profiles',  'attacker-profiles',  'Attacker Profiles',  'Threat actor profiles used to drive attack simulation + prioritisation scoring',         'Swords',       'scoping', 9,  true, false, 'released'),
    ('relationships',      'relationships',      'Relationships',      'Asset-to-asset relationships for attack-path modelling',                                 'Link',         'scoping', 10, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

-- Prioritisation cluster ---------------------------------------------------

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('priority_rules',     'priority-rules',     'Priority Rules',     'Declarative priority classification rules (P0..P3)',                                      'Sliders',      'prioritization', 24, true, false, 'released'),
    ('risk_analysis',      'risk-analysis',      'Risk Analysis',      'Aggregate risk dashboards across assets + findings',                                     'BarChart',     'prioritization', 25, true, false, 'released'),
    ('business_impact',    'business-impact',    'Business Impact',    'Business impact scoring weighted by business-services mapping',                          'Building',     'prioritization', 26, true, false, 'released'),
    ('risk_scoring',       'risk-scoring',       'Risk Scoring',       'Risk scoring config — CVSS / EPSS / KEV / custom weights',                               'TrendingUp',   'prioritization', 27, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

-- Validation cluster -------------------------------------------------------

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('compensating_controls','compensating-controls','Compensating Controls','Controls that reduce finding severity (WAF, EDR, IPS, …)',                            'ShieldCheck',  'validation',     33, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

-- Mobilisation cluster -----------------------------------------------------

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('workflows',          'workflows',          'Workflows',          'Trigger-action automation for finding lifecycle (assignment, notification, sync)',        'GitPullRequest','mobilization',  43, true, false, 'released'),
    ('remediation_tasks',  'remediation-tasks',  'Remediation Tasks',  'Operator-facing task queue backed by the remediation engine',                            'CheckSquare',  'mobilization',   44, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

-- Insights cluster ---------------------------------------------------------

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('ctem_maturity',      'ctem-maturity',      'CTEM Maturity',      'Per-tenant CTEM invariant health — F1-F4, B1-B7, O1-O3',                                 'ShieldCheck',  'insights',       52, true, false, 'released'),
    ('executive_summary',  'executive-summary',  'Executive Summary',  'Board-ready PDF rollup of risk, breaches, SLAs',                                         'FileText',     'insights',       53, true, false, 'released'),
    ('mitre_coverage',     'mitre-coverage',     'MITRE Coverage',     'MITRE ATT&CK technique coverage across detections + controls',                           'Shield',       'insights',       54, true, false, 'released'),
    ('sbom_export',        'sbom-export',        'SBOM Export',        'Export Software Bill of Materials in CycloneDX / SPDX',                                  'Download',     'insights',       55, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

-- Settings cluster (scanner orchestration) ---------------------------------

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('scanner_templates',  'scanner-templates',  'Scanner Templates',  'Catalogue of Nuclei / Gitleaks / Semgrep templates',                                     'FileCode',     'settings',       10, true, false, 'released'),
    ('template_sources',   'template-sources',   'Template Sources',   'Upstream git sources that templates are synced from',                                   'Database',     'settings',       11, true, false, 'released'),
    ('scan_pipelines',     'scan-pipelines',     'Scan Pipelines',     'Multi-step scan pipelines (scope → fingerprint → scan → triage)',                        'GitBranch',    'settings',       12, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

COMMIT;
