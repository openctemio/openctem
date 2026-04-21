BEGIN;

DELETE FROM modules WHERE id IN (
    'attack_surface', 'scope_config', 'business_services', 'ctem_cycles',
    'attacker_profiles', 'relationships',
    'priority_rules', 'risk_analysis', 'business_impact', 'risk_scoring',
    'compensating_controls',
    'workflows', 'remediation_tasks',
    'ctem_maturity', 'executive_summary', 'mitre_coverage', 'sbom_export',
    'scanner_templates', 'template_sources', 'scan_pipelines'
);

COMMIT;
