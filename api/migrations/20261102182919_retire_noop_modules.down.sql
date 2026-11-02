-- Restore the retired module rows as the previous registry migration wrote
-- them, and make risk_scoring and suppressions switchable again. Not restored:
-- the organizations' switches that the up migration dropped, and the original
-- module_id of the permissions moved to a parent (scans:profiles:* back to
-- scan_profiles; the other retired modules owned no permission rows).
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status, parent_module_id)
VALUES
    ('crown_jewels', 'crown-jewels', 'Crown Jewels', 'Business-critical assets flagged for heightened prioritisation and monitoring', 'Crown', 'scoping', 12, TRUE, false, 'released', NULL),
    ('risk_analysis', 'risk-analysis', 'Risk Analysis', 'Aggregate risk dashboards across assets + findings', 'BarChart', 'prioritization', 25, TRUE, false, 'released', NULL),
    ('business_impact', 'business-impact', 'Business Impact', 'Business impact scoring weighted by business-services mapping', 'Building', 'prioritization', 26, TRUE, false, 'released', NULL),
    ('ctem_maturity', 'ctem-maturity', 'CTEM Maturity', 'Per-tenant CTEM invariant health — F1-F4, B1-B7, O1-O3', 'ShieldCheck', 'insights', 52, TRUE, false, 'released', NULL),
    ('executive_summary', 'executive-summary', 'Executive Summary', 'Board-ready PDF rollup of risk, breaches, SLAs', 'FileText', 'insights', 53, TRUE, false, 'released', NULL),
    ('mitre_coverage', 'mitre-coverage', 'MITRE Coverage', 'MITRE ATT&CK technique coverage across detections + controls', 'Shield', 'insights', 54, TRUE, false, 'released', NULL),
    ('sbom_export', 'sbom-export', 'SBOM Export', 'Export Software Bill of Materials in CycloneDX / SPDX', 'Download', 'insights', 55, TRUE, false, 'released', NULL),
    ('integrations.scm', 'scm', 'SCM Integrations', 'Source code management integrations', 'GitBranch', 'settings', 1, TRUE, false, 'released', 'integrations'),
    ('integrations.notifications', 'notifications', 'Notification Channels', 'Notification channel integrations', 'Bell', 'settings', 2, TRUE, true, 'released', 'integrations'),
    ('integrations.ticketing', 'ticketing', 'Ticketing', 'Issue tracking integrations', 'Ticket', 'settings', 3, TRUE, false, 'released', 'integrations'),
    ('integrations.cloud', 'cloud', 'Cloud Providers', 'Cloud provider integrations', 'Cloud', 'settings', 4, TRUE, false, 'released', 'integrations'),
    ('integrations.siem', 'siem', 'SIEM', 'SIEM integrations', 'Shield', 'settings', 5, TRUE, false, 'released', 'integrations'),
    ('integrations.scanners', 'scanners', 'Scanners', 'External scanner integrations', 'Search', 'settings', 6, TRUE, false, 'released', 'integrations'),
    ('integrations.api', 'api_int', 'API Integrations', 'API integrations', 'Zap', 'settings', 8, TRUE, false, 'released', 'integrations'),
    ('integrations.pipelines', 'pipelines_int', 'Pipeline Integrations', 'CI/CD pipeline integrations', 'GitPullRequest', 'settings', 9, TRUE, false, 'released', 'integrations'),
    ('tools', 'tools', 'Tools', 'Security tools and capabilities management', 'Wrench', 'operations', 81, TRUE, false, 'released', NULL),
    ('scan_profiles', 'scan_profiles', 'Scan Profiles', 'Scan configuration profiles', 'Sliders', 'operations', 83, TRUE, false, 'released', NULL)
ON CONFLICT (id) DO NOTHING;

UPDATE modules SET is_core = false WHERE id IN ('risk_scoring', 'suppressions');
UPDATE permissions SET module_id = 'scan_profiles'
 WHERE id IN ('scans:profiles:read', 'scans:profiles:write', 'scans:profiles:delete');
