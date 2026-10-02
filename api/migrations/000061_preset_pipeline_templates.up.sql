-- =============================================================================
-- Migration 000061: Preset Pipeline Templates
-- OpenCTEM OSS Edition
-- =============================================================================
-- Creates 6 system pipeline templates demonstrating common security workflow
-- patterns: parallel execution, sequential scanning, complex DAGs, and
-- scheduled monitoring.
--
-- Templates use the system tenant from migration 000058.
-- System templates (is_system_template=true) can be used directly or cloned.
-- Source: old migration 000090
-- =============================================================================

-- =============================================================================
-- 1. SUBDOMAIN ENUMERATION (Parallel Tools Pattern)
-- =============================================================================
-- [amass] ────────┐
--                 ├──► [dedupe_merge] ──► [dns_resolve]
-- [subfinder] ────┘
-- =============================================================================
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    triggers, settings, is_active, is_system_template, tags
) VALUES (
    'a0000001-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000000',
    'Subdomain Enumeration',
    'Comprehensive subdomain discovery using multiple tools in parallel. Results are deduplicated and DNS-resolved.',
    1,
    '[{"type": "manual"}, {"type": "api"}]'::jsonb,
    '{"max_parallel_steps": 3, "fail_fast": false, "timeout_seconds": 7200, "notify_on_failure": true}'::jsonb,
    true, true,
    ARRAY['recon', 'subdomain', 'discovery', 'preset']
)
ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    triggers = EXCLUDED.triggers,
    settings = EXCLUDED.settings,
    tags = EXCLUDED.tags,
    updated_at = NOW();

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    -- Step 1a: Amass (parallel with subfinder)
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
    -- Step 1b: Subfinder (parallel with amass)
    (
        'b0000001-0001-0000-0000-000000000002',
        'a0000001-0000-0000-0000-000000000001',
        'subfinder_enum', 'Subfinder Enumeration',
        'Fast passive subdomain discovery using multiple sources',
        2, 'subfinder', ARRAY['recon', 'subdomain'],
        '{"all": true, "threads": 30, "timeout": 30}'::jsonb,
        900, ARRAY[]::text[],
        'always', 2, 30,
        300, 100
    ),
    -- Step 2: Dedupe and Merge (depends on both)
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
    -- Step 3: DNS Resolution
    (
        'b0000001-0001-0000-0000-000000000004',
        'a0000001-0000-0000-0000-000000000001',
        'dns_resolve', 'DNS Resolution',
        'Resolve subdomains to validate and get IP addresses',
        4, 'dnsx', ARRAY['recon', 'dns'],
        '{"resp": true, "a": true, "aaaa": true, "cname": true, "threads": 100}'::jsonb,
        600, ARRAY['dedupe_merge'],
        'always', 1, 30,
        200, 400
    )
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- 2. PORT SCANNING PIPELINE (Sequential Pattern)
-- =============================================================================
-- [fast_scan] ──► [deep_scan] ──► [service_detect]
-- =============================================================================
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    triggers, settings, is_active, is_system_template, tags
) VALUES (
    'a0000001-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000000',
    'Port Scanning',
    'Fast port discovery followed by detailed service detection on open ports.',
    1,
    '[{"type": "manual"}, {"type": "api"}]'::jsonb,
    '{"max_parallel_steps": 2, "fail_fast": false, "timeout_seconds": 7200, "notify_on_failure": true}'::jsonb,
    true, true,
    ARRAY['recon', 'ports', 'discovery', 'preset']
)
ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    triggers = EXCLUDED.triggers,
    settings = EXCLUDED.settings,
    tags = EXCLUDED.tags,
    updated_at = NOW();

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    (
        'b0000001-0002-0000-0000-000000000001',
        'a0000001-0000-0000-0000-000000000002',
        'fast_port_scan', 'Fast Port Scan',
        'Quick SYN scan of top 1000 ports using naabu',
        1, 'naabu', ARRAY['recon', 'ports'],
        '{"top_ports": "1000", "rate": 5000, "retries": 2}'::jsonb,
        600, ARRAY[]::text[],
        'always', 1, 30,
        200, 100
    ),
    (
        'b0000001-0002-0000-0000-000000000002',
        'a0000001-0000-0000-0000-000000000002',
        'deep_port_scan', 'Deep Port Scan',
        'Detailed scan of all 65535 ports on responsive hosts',
        2, 'naabu', ARRAY['recon', 'ports'],
        '{"ports": "1-65535", "rate": 3000, "retries": 3, "scan_type": "syn"}'::jsonb,
        1800, ARRAY['fast_port_scan'],
        'always', 1, 60,
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
    )
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- 3. FULL RECONNAISSANCE (Complex Parallel DAG)
-- =============================================================================
--                    ┌──► [http_probe] ──┬──► [screenshot]
-- [subdomain_enum] ──┤                   │
--                    └──► [port_scan] ───┴──► [tech_detect] ──► [vuln_scan]
-- =============================================================================
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    triggers, settings, is_active, is_system_template, tags
) VALUES (
    'a0000001-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000000',
    'Full Reconnaissance',
    'Complete reconnaissance workflow: subdomain discovery, HTTP probing, port scanning, screenshots, and technology detection.',
    1,
    '[{"type": "manual"}, {"type": "schedule", "schedule": "0 2 * * *"}]'::jsonb,
    '{"max_parallel_steps": 4, "fail_fast": false, "timeout_seconds": 14400, "notify_on_complete": true, "notify_on_failure": true}'::jsonb,
    true, true,
    ARRAY['recon', 'full', 'comprehensive', 'preset']
)
ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    triggers = EXCLUDED.triggers,
    settings = EXCLUDED.settings,
    tags = EXCLUDED.tags,
    updated_at = NOW();

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    (
        'b0000001-0003-0000-0000-000000000001',
        'a0000001-0000-0000-0000-000000000003',
        'subdomain_enum', 'Subdomain Enumeration',
        'Discover subdomains using multiple tools',
        1, 'subfinder', ARRAY['recon', 'subdomain'],
        '{"all": true, "threads": 50, "timeout": 60}'::jsonb,
        1800, ARRAY[]::text[],
        'always', 2, 60,
        200, 50
    ),
    (
        'b0000001-0003-0000-0000-000000000002',
        'a0000001-0000-0000-0000-000000000003',
        'http_probe', 'HTTP Probing',
        'Probe discovered hosts for live HTTP/HTTPS services',
        2, 'httpx', ARRAY['recon', 'http'],
        '{"threads": 100, "status_code": true, "title": true, "tech_detect": true, "follow_redirects": true}'::jsonb,
        1200, ARRAY['subdomain_enum'],
        'always', 2, 30,
        100, 200
    ),
    (
        'b0000001-0003-0000-0000-000000000003',
        'a0000001-0000-0000-0000-000000000003',
        'port_scan', 'Port Scanning',
        'Scan for open ports on discovered hosts',
        3, 'naabu', ARRAY['recon', 'ports'],
        '{"top_ports": "1000", "rate": 3000}'::jsonb,
        1200, ARRAY['subdomain_enum'],
        'always', 1, 60,
        300, 200
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
        'b0000001-0003-0000-0000-000000000006',
        'a0000001-0000-0000-0000-000000000003',
        'vuln_scan', 'Vulnerability Scanning',
        'Scan for known vulnerabilities based on detected technologies',
        6, 'nuclei', ARRAY['vulnerability', 'scan'],
        '{"severity": ["critical", "high", "medium"], "templates": ["cves", "exposures", "misconfigurations"], "rate_limit": 150}'::jsonb,
        3600, ARRAY['tech_detect'],
        'always', 2, 120,
        200, 500
    )
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- 4. WEB VULNERABILITY SCAN (Parallel Scanners Pattern)
-- =============================================================================
-- [crawl] ──┬──► [xss_scan]
--           ├──► [sqli_scan]    ──► [report_gen]
--           └──► [nuclei_scan] ─┘
-- =============================================================================
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    triggers, settings, is_active, is_system_template, tags
) VALUES (
    'a0000001-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000000',
    'Web Vulnerability Scan',
    'Comprehensive web application vulnerability scanning with specialized tools for XSS, SQLi, and common CVEs.',
    1,
    '[{"type": "manual"}, {"type": "api"}, {"type": "webhook"}]'::jsonb,
    '{"max_parallel_steps": 4, "fail_fast": false, "timeout_seconds": 10800, "notify_on_complete": true, "notify_on_failure": true}'::jsonb,
    true, true,
    ARRAY['vulnerability', 'web', 'dast', 'preset']
)
ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    triggers = EXCLUDED.triggers,
    settings = EXCLUDED.settings,
    tags = EXCLUDED.tags,
    updated_at = NOW();

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    (
        'b0000001-0004-0000-0000-000000000001',
        'a0000001-0000-0000-0000-000000000004',
        'web_crawl', 'Web Crawling',
        'Crawl target web application to discover endpoints and parameters',
        1, 'katana', ARRAY['recon', 'crawl'],
        '{"depth": 3, "js_crawl": true, "form_extraction": true, "headless": true, "timeout": 30}'::jsonb,
        1800, ARRAY[]::text[],
        'always', 2, 60,
        200, 50
    ),
    (
        'b0000001-0004-0000-0000-000000000002',
        'a0000001-0000-0000-0000-000000000004',
        'xss_scan', 'XSS Scanning',
        'Scan for Cross-Site Scripting vulnerabilities',
        2, 'dalfox', ARRAY['vulnerability', 'xss'],
        '{"blind": true, "follow_redirects": true, "workers": 20}'::jsonb,
        1800, ARRAY['web_crawl'],
        'always', 1, 60,
        50, 200
    ),
    (
        'b0000001-0004-0000-0000-000000000003',
        'a0000001-0000-0000-0000-000000000004',
        'sqli_scan', 'SQL Injection Scanning',
        'Scan for SQL Injection vulnerabilities',
        3, 'sqlmap', ARRAY['vulnerability', 'sqli'],
        '{"level": 3, "risk": 2, "batch": true, "threads": 5}'::jsonb,
        2400, ARRAY['web_crawl'],
        'always', 1, 120,
        200, 200
    ),
    (
        'b0000001-0004-0000-0000-000000000004',
        'a0000001-0000-0000-0000-000000000004',
        'nuclei_cve', 'CVE Scanning',
        'Scan for known CVEs using Nuclei templates',
        4, 'nuclei', ARRAY['vulnerability', 'scan'],
        '{"severity": ["critical", "high"], "templates": ["cves", "vulnerabilities"], "rate_limit": 100}'::jsonb,
        2400, ARRAY['web_crawl'],
        'always', 2, 60,
        350, 200
    ),
    (
        'b0000001-0004-0000-0000-000000000005',
        'a0000001-0000-0000-0000-000000000004',
        'report_gen', 'Report Generation',
        'Generate consolidated vulnerability report',
        5, NULL, ARRAY['report', 'aggregate'],
        '{"format": ["html", "json", "pdf"], "include_evidence": true}'::jsonb,
        600, ARRAY['xss_scan', 'sqli_scan', 'nuclei_cve'],
        'always', 0, 0,
        200, 350
    )
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- 5. API SECURITY TESTING (Sequential with fail_fast)
-- =============================================================================
-- [api_discovery] ──► [api_fuzzing] ──► [auth_testing] ──► [rate_limit_test]
-- =============================================================================
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    triggers, settings, is_active, is_system_template, tags
) VALUES (
    'a0000001-0000-0000-0000-000000000005',
    '00000000-0000-0000-0000-000000000000',
    'API Security Testing',
    'Comprehensive API security testing including endpoint discovery, fuzzing, authentication testing, and rate limit checks.',
    1,
    '[{"type": "manual"}, {"type": "api"}]'::jsonb,
    '{"max_parallel_steps": 2, "fail_fast": true, "timeout_seconds": 7200, "notify_on_complete": true, "notify_on_failure": true}'::jsonb,
    true, true,
    ARRAY['api', 'security', 'dast', 'preset']
)
ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    triggers = EXCLUDED.triggers,
    settings = EXCLUDED.settings,
    tags = EXCLUDED.tags,
    updated_at = NOW();

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    (
        'b0000001-0005-0000-0000-000000000001',
        'a0000001-0000-0000-0000-000000000005',
        'api_discovery', 'API Discovery',
        'Discover API endpoints from OpenAPI specs, JS files, and common paths',
        1, 'kiterunner', ARRAY['api', 'discovery'],
        '{"wordlist": "routes-large", "ignore_length": "0", "threads": 50}'::jsonb,
        1200, ARRAY[]::text[],
        'always', 1, 60,
        200, 50
    ),
    (
        'b0000001-0005-0000-0000-000000000002',
        'a0000001-0000-0000-0000-000000000005',
        'api_fuzz', 'API Fuzzing',
        'Fuzz API endpoints for unexpected behavior and vulnerabilities',
        2, 'ffuf', ARRAY['api', 'fuzzing'],
        '{"wordlist": "api-params", "mc": "200,201,204,301,302,307,401,403,500", "threads": 40}'::jsonb,
        1800, ARRAY['api_discovery'],
        'always', 1, 60,
        200, 200
    ),
    (
        'b0000001-0005-0000-0000-000000000003',
        'a0000001-0000-0000-0000-000000000005',
        'auth_test', 'Authentication Testing',
        'Test for authentication bypasses and weak configurations',
        3, 'nuclei', ARRAY['api', 'auth'],
        '{"templates": ["http/exposures", "http/misconfiguration"], "tags": "auth,jwt,oauth"}'::jsonb,
        1200, ARRAY['api_fuzz'],
        'always', 2, 60,
        200, 350
    ),
    (
        'b0000001-0005-0000-0000-000000000004',
        'a0000001-0000-0000-0000-000000000005',
        'rate_limit_test', 'Rate Limit Testing',
        'Test API rate limiting implementation',
        4, NULL, ARRAY['api', 'rate_limit'],
        '{"requests_per_second": 100, "duration_seconds": 30, "check_headers": true}'::jsonb,
        300, ARRAY['auth_test'],
        'always', 0, 0,
        200, 500
    )
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- 6. CONTINUOUS MONITORING (Lightweight, Scheduled)
-- =============================================================================
-- [dns_check] ──┬──► [http_check] ──► [cert_check]
--               │
-- [port_check] ─┘
-- =============================================================================
INSERT INTO pipeline_templates (
    id, tenant_id, name, description, version,
    triggers, settings, is_active, is_system_template, tags
) VALUES (
    'a0000001-0000-0000-0000-000000000006',
    '00000000-0000-0000-0000-000000000000',
    'Continuous Monitoring',
    'Lightweight pipeline for continuous asset monitoring. Designed for frequent scheduled execution.',
    1,
    '[{"type": "schedule", "schedule": "0 */4 * * *"}]'::jsonb,
    '{"max_parallel_steps": 3, "fail_fast": false, "timeout_seconds": 1800, "notify_on_failure": true}'::jsonb,
    true, true,
    ARRAY['monitoring', 'continuous', 'lightweight', 'preset']
)
ON CONFLICT (id) DO UPDATE SET
    description = EXCLUDED.description,
    triggers = EXCLUDED.triggers,
    settings = EXCLUDED.settings,
    tags = EXCLUDED.tags,
    updated_at = NOW();

INSERT INTO pipeline_steps (
    id, pipeline_id, step_key, name, description, step_order,
    tool, capabilities, config, timeout_seconds, depends_on,
    condition_type, max_retries, retry_delay_seconds,
    ui_position_x, ui_position_y
) VALUES
    (
        'b0000001-0006-0000-0000-000000000001',
        'a0000001-0000-0000-0000-000000000006',
        'dns_check', 'DNS Resolution',
        'Verify DNS records and detect changes',
        1, 'dnsx', ARRAY['monitoring', 'dns'],
        '{"a": true, "resp": true, "retry": 2}'::jsonb,
        300, ARRAY[]::text[],
        'always', 1, 30,
        100, 100
    ),
    (
        'b0000001-0006-0000-0000-000000000002',
        'a0000001-0000-0000-0000-000000000006',
        'port_check', 'Port Availability',
        'Check if critical ports are responsive',
        2, 'naabu', ARRAY['monitoring', 'ports'],
        '{"ports": "80,443,8080,8443,22,3389", "rate": 1000}'::jsonb,
        300, ARRAY[]::text[],
        'always', 1, 30,
        300, 100
    ),
    (
        'b0000001-0006-0000-0000-000000000003',
        'a0000001-0000-0000-0000-000000000006',
        'http_check', 'HTTP Availability',
        'Check HTTP service availability and response times',
        3, 'httpx', ARRAY['monitoring', 'http'],
        '{"status_code": true, "response_time": true, "title": true}'::jsonb,
        300, ARRAY['dns_check', 'port_check'],
        'always', 2, 30,
        200, 250
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

-- =============================================================================
-- SUMMARY
-- =============================================================================
-- 6 preset pipeline templates, 25 total steps:
--
-- 1. Subdomain Enumeration  (4 steps) - Parallel discovery → merge → resolve
-- 2. Port Scanning           (3 steps) - Fast scan → deep scan → service detect
-- 3. Full Reconnaissance     (6 steps) - Complex DAG with parallel branches
-- 4. Web Vulnerability Scan  (5 steps) - Crawl → parallel vuln scans → report
-- 5. API Security Testing    (4 steps) - Sequential with fail_fast
-- 6. Continuous Monitoring    (4 steps) - Lightweight scheduled checks
-- =============================================================================
