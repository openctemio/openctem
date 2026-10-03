-- Restore the 000061 preset pipelines and the recon tool rows as they were.

UPDATE tools SET supported_targets = '{}', output_formats = '{}', updated_at = NOW()
WHERE tenant_id IS NULL AND name IN ('subfinder', 'dnsx', 'naabu', 'httpx', 'katana');

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    (
        'b0000001-0001-0000-0000-000000000001',
        'a0000001-0000-0000-0000-000000000001',
        'amass_enum', 'Amass Enumeration',
        'Comprehensive subdomain enumeration using OWASP Amass',
        1, 'amass', ARRAY['recon', 'subdomain'],
        '{"mode": "enum", "passive": true, "timeout": 30, "max_depth": 3}'::jsonb,
        1800, ARRAY[]::text[],
        'always', 2, 60,
        100, 100
    ),
    (
        'b0000001-0001-0000-0000-000000000003',
        'a0000001-0000-0000-0000-000000000001',
        'dedupe_merge', 'Deduplicate Results',
        'Merge and deduplicate subdomains from all sources',
        3, NULL, ARRAY['data', 'transform'],
        '{"remove_wildcards": true, "sort": true}'::jsonb,
        300, ARRAY['amass_enum', 'subfinder_enum'],
        'always', 0, 0,
        200, 250
    ),
    (
        'b0000001-0002-0000-0000-000000000003',
        'a0000001-0000-0000-0000-000000000002',
        'service_detect', 'Service Detection',
        'Detect services and versions on open ports',
        3, 'nmap', ARRAY['recon', 'service'],
        '{"scan_type": "-sV", "version_intensity": 5, "scripts": "default"}'::jsonb,
        1200, ARRAY['deep_port_scan'],
        'always', 2, 60,
        200, 400
    ),
    (
        'b0000001-0003-0000-0000-000000000004',
        'a0000001-0000-0000-0000-000000000003',
        'screenshot', 'Screenshot Capture',
        'Capture screenshots of live web services',
        4, 'gowitness', ARRAY['recon', 'screenshot'],
        '{"threads": 10, "timeout": 30}'::jsonb,
        1800, ARRAY['http_probe'],
        'always', 1, 60,
        50, 350
    ),
    (
        'b0000001-0003-0000-0000-000000000005',
        'a0000001-0000-0000-0000-000000000003',
        'tech_detect', 'Technology Detection',
        'Identify technologies, frameworks, and CMS',
        5, 'wappalyzer', ARRAY['recon', 'tech'],
        '{"recursive": true, "max_depth": 2}'::jsonb,
        900, ARRAY['http_probe', 'port_scan'],
        'always', 1, 30,
        200, 350
    ),
    (
        'b0000001-0006-0000-0000-000000000004',
        'a0000001-0000-0000-0000-000000000006',
        'cert_check', 'Certificate Validation',
        'Check SSL/TLS certificate validity and expiration',
        4, 'tlsx', ARRAY['monitoring', 'tls'],
        '{"expired": true, "self_signed": true, "mismatched": true, "json": true}'::jsonb,
        300, ARRAY['http_check'],
        'always', 1, 30,
        200, 400
    )
ON CONFLICT (id) DO NOTHING;

UPDATE pipeline_steps SET tool_id = t.id FROM tools t
WHERE pipeline_steps.tool = t.name AND t.tenant_id IS NULL AND pipeline_steps.tool_id IS NULL
  AND pipeline_steps.id::text LIKE 'b0000001-%';

UPDATE pipeline_steps SET depends_on = ARRAY['dedupe_merge'], step_order = 4
WHERE id = 'b0000001-0001-0000-0000-000000000004';
UPDATE pipeline_steps SET step_order = 2 WHERE id = 'b0000001-0001-0000-0000-000000000002';
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'ports'], config = config - 'scan_type'
WHERE id = 'b0000001-0002-0000-0000-000000000001';
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'ports'], config = config - 'scan_type' || '{"scan_type": "syn"}'::jsonb
WHERE id = 'b0000001-0002-0000-0000-000000000002';
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'ports'] WHERE id = 'b0000001-0003-0000-0000-000000000003';
UPDATE pipeline_steps SET capabilities = ARRAY['vulnerability', 'scan'], depends_on = ARRAY['tech_detect'], step_order = 6
WHERE id = 'b0000001-0003-0000-0000-000000000006';
UPDATE pipeline_steps SET capabilities = ARRAY['monitoring', 'dns'] WHERE id = 'b0000001-0006-0000-0000-000000000001';
UPDATE pipeline_steps SET capabilities = ARRAY['monitoring', 'ports'] WHERE id = 'b0000001-0006-0000-0000-000000000002';
UPDATE pipeline_steps SET capabilities = ARRAY['monitoring', 'http'] WHERE id = 'b0000001-0006-0000-0000-000000000003';

UPDATE pipeline_templates SET description = 'Comprehensive subdomain discovery using multiple tools in parallel. Results are deduplicated and DNS-resolved.', updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000001';
UPDATE pipeline_templates SET description = 'Fast port discovery followed by detailed service detection on open ports.', updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000002';
UPDATE pipeline_templates SET description = 'Complete reconnaissance workflow: subdomain discovery, HTTP probing, port scanning, screenshots, and technology detection.', updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000003';
UPDATE pipeline_templates SET description = 'Lightweight pipeline for continuous asset monitoring. Designed for frequent scheduled execution.', updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000006';

UPDATE pipeline_templates SET is_active = TRUE, updated_at = NOW()
WHERE id IN ('a0000001-0000-0000-0000-000000000004', 'a0000001-0000-0000-0000-000000000005');
