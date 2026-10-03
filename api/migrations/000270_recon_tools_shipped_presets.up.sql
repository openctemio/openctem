-- Recon tools shipped in the sensor image, and preset pipelines that use
-- only shipped tools (api RFC-036 P0, defects E2 and E7).
--
-- 1. The recon tools (subfinder, dnsx, naabu, httpx, katana; migration
--    000055) now run on sensors: the full and platform sensor images ship
--    them pinned, and the SDK runs them as scanners. They get their category,
--    the target types they take and their version command, like the other
--    built-in tools. Capabilities stay as 000055 seeded them (the sensor
--    advertises exactly these).
--
-- 2. The system preset pipelines (000061) referenced tools no sensor ships
--    (amass, nmap, gowitness, wappalyzer, dalfox, sqlmap, kiterunner, ffuf,
--    tlsx), tool-less steps nothing executes (dedupe, report, rate-limit
--    test), and capability names the tool catalog does not give the tool
--    ("ports", "crawl", "monitoring", "vulnerability"...). The step check at
--    queue time (SecurityValidator.ValidateStepConfig) refused every one of
--    them, so no preset could run. The four discovery presets keep only
--    steps with shipped tools and catalog capabilities; "Web Vulnerability
--    Scan" and "API Security Testing" are deactivated: their tools are not
--    shipped and they are intrusive (fuzzing, SQL injection), which RFC-036
--    O3 keeps opt-in. Removing a step deletes its step runs (ON DELETE
--    CASCADE); a run of these steps could only have failed at queue time.
--
-- Idempotent. Rows a tenant cloned from a preset are copies and unaffected.

-- 1. Recon tool metadata ------------------------------------------------------

UPDATE tools t SET
    category_id       = COALESCE(t.category_id, (SELECT id FROM tool_categories WHERE name = 'recon' AND tenant_id IS NULL)),
    supported_targets = v.targets,
    output_formats    = ARRAY['json'],
    version_cmd       = COALESCE(NULLIF(t.version_cmd, ''), v.name || ' -version'),
    github_url        = COALESCE(NULLIF(t.github_url, ''), 'https://github.com/projectdiscovery/' || v.name),
    updated_at        = NOW()
FROM (VALUES
    ('subfinder', ARRAY['domain']),
    ('dnsx',      ARRAY['domain', 'host']),
    ('naabu',     ARRAY['domain', 'host', 'ip']),
    ('httpx',     ARRAY['domain', 'host', 'ip', 'url', 'service']),
    ('katana',    ARRAY['url', 'service'])
) AS v(name, targets)
WHERE t.name = v.name AND t.tenant_id IS NULL;

-- 2. Preset pipelines -----------------------------------------------------------

-- Subdomain Enumeration: subfinder -> dnsx.
DELETE FROM pipeline_steps WHERE id IN (
    'b0000001-0001-0000-0000-000000000001',  -- amass_enum (amass)
    'b0000001-0001-0000-0000-000000000003'   -- dedupe_merge (no tool)
);
UPDATE pipeline_steps SET depends_on = ARRAY['subfinder_enum'], step_order = 2
WHERE id = 'b0000001-0001-0000-0000-000000000004';
UPDATE pipeline_steps SET step_order = 1
WHERE id = 'b0000001-0001-0000-0000-000000000002';
UPDATE pipeline_templates SET
    description = 'Passive subdomain discovery (subfinder), then DNS resolution of the results (dnsx).',
    updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000001';

-- Port Scanning: naabu (TCP connect, no raw sockets).
DELETE FROM pipeline_steps WHERE id = 'b0000001-0002-0000-0000-000000000003';  -- service_detect (nmap)
UPDATE pipeline_steps SET
    capabilities = ARRAY['recon', 'portscan'],
    config = config - 'scan_type' || '{"scan_type": "connect"}'::jsonb
WHERE id IN ('b0000001-0002-0000-0000-000000000001', 'b0000001-0002-0000-0000-000000000002');
UPDATE pipeline_templates SET
    description = 'Fast port discovery, then a full port scan of the responsive hosts (naabu, TCP connect).',
    updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000002';

-- Full Reconnaissance: subfinder -> httpx + naabu -> nuclei.
DELETE FROM pipeline_steps WHERE id IN (
    'b0000001-0003-0000-0000-000000000004',  -- screenshot (gowitness)
    'b0000001-0003-0000-0000-000000000005'   -- tech_detect (wappalyzer)
);
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'portscan']
WHERE id = 'b0000001-0003-0000-0000-000000000003';
UPDATE pipeline_steps SET
    capabilities = ARRAY['dast'],
    depends_on = ARRAY['http_probe', 'port_scan'],
    step_order = 4
WHERE id = 'b0000001-0003-0000-0000-000000000006';
UPDATE pipeline_templates SET
    description = 'Subdomain discovery (subfinder), HTTP probing (httpx) and port discovery (naabu), then a nuclei scan.',
    updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000003';

-- Continuous Monitoring: dnsx + naabu -> httpx.
DELETE FROM pipeline_steps WHERE id = 'b0000001-0006-0000-0000-000000000004';  -- cert_check (tlsx)
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'dns']
WHERE id = 'b0000001-0006-0000-0000-000000000001';
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'portscan']
WHERE id = 'b0000001-0006-0000-0000-000000000002';
UPDATE pipeline_steps SET capabilities = ARRAY['recon', 'http']
WHERE id = 'b0000001-0006-0000-0000-000000000003';
UPDATE pipeline_templates SET
    description = 'Scheduled DNS, port and HTTP checks of known assets (dnsx, naabu, httpx).',
    updated_at = NOW()
WHERE id = 'a0000001-0000-0000-0000-000000000006';

-- Intrusive presets whose tools no sensor ships: off.
UPDATE pipeline_templates SET is_active = FALSE, updated_at = NOW()
WHERE id IN ('a0000001-0000-0000-0000-000000000004', 'a0000001-0000-0000-0000-000000000005');
