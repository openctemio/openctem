-- =============================================================================
-- Migration 000055: Seed Additional Capabilities + Tool-Capability Links
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds 11 capabilities missing from initial seed (000030):
--   Recon:    dns, tech_detect, url_discovery
--   Security: api, cloud, mobile, compliance, security_analysis
--   Analysis: pipeline, reporting, ai_triage
-- Also links existing recon tools to their capabilities via junction table.
-- NOTE: All capability names use snake_case convention.
-- Source: old migrations 000105, 000143
-- =============================================================================

-- =============================================================================
-- 1. Recon Capabilities (from old 000105)
-- =============================================================================
INSERT INTO capabilities (tenant_id, name, display_name, description, icon, color, category, is_builtin, sort_order) VALUES
    (NULL, 'dns', 'DNS', 'DNS resolution and record enumeration', 'globe', 'teal', 'recon', true, 25),
    (NULL, 'tech_detect', 'Tech Detect', 'Technology fingerprinting and detection', 'cpu', 'violet', 'recon', true, 26),
    (NULL, 'url_discovery', 'URL Discovery', 'URL and endpoint discovery', 'link', 'cyan', 'recon', true, 27)

ON CONFLICT (tenant_id, name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    category = EXCLUDED.category,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

-- =============================================================================
-- 2. Security Capabilities (from old 000143)
-- =============================================================================
INSERT INTO capabilities (tenant_id, name, display_name, description, icon, color, category, is_builtin, sort_order) VALUES
    (NULL, 'api', 'API Security', 'API endpoint security testing and vulnerability detection', 'plug', 'blue', 'security', true, 7),
    (NULL, 'cloud', 'Cloud Security', 'Cloud infrastructure and configuration security scanning', 'cloud', 'sky', 'security', true, 8),
    (NULL, 'mobile', 'Mobile Security', 'Mobile application security analysis (iOS/Android)', 'smartphone', 'purple', 'security', true, 9),
    (NULL, 'compliance', 'Compliance', 'Regulatory compliance checking (SOC2, HIPAA, PCI-DSS, etc.)', 'shield-check', 'emerald', 'security', true, 14)

ON CONFLICT (tenant_id, name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    category = EXCLUDED.category,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

-- =============================================================================
-- 3. Analysis Capabilities (from old 000105 + 000143)
-- =============================================================================
INSERT INTO capabilities (tenant_id, name, display_name, description, icon, color, category, is_builtin, sort_order) VALUES
    (NULL, 'pipeline', 'Pipeline', 'Multi-step scan pipeline execution', 'workflow', 'blue', 'analysis', true, 31),
    (NULL, 'reporting', 'Reporting', 'Security report generation and export', 'file-chart-line', 'slate', 'analysis', true, 32),
    (NULL, 'ai_triage', 'AI Triage', 'AI-powered vulnerability triage and prioritization', 'brain', 'violet', 'analysis', true, 33)

ON CONFLICT (tenant_id, name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    category = EXCLUDED.category,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

-- =============================================================================
-- 4. Missing Security Capability
-- =============================================================================
-- Referenced by semgrep (['sast', 'security_analysis']) and
-- checkov (['iac', 'security_analysis']) but not in initial seed (000030).
INSERT INTO capabilities (tenant_id, name, display_name, description, icon, color, category, is_builtin, sort_order) VALUES
    (NULL, 'security_analysis', 'Security Analysis', 'General security analysis and code review', 'shield', 'amber', 'security', true, 15)

ON CONFLICT (tenant_id, name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    category = EXCLUDED.category,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

-- =============================================================================
-- 5. Recon Scanner Tools (from old 000105)
-- =============================================================================

-- Subfinder - Subdomain enumeration
INSERT INTO tools (tenant_id, name, display_name, description, capabilities, install_method, is_active, is_builtin, tags)
SELECT NULL, 'subfinder', 'Subfinder', 'Passive subdomain enumeration using multiple sources',
       ARRAY['recon', 'subdomain'], 'go', true, true, ARRAY['recon', 'subdomain', 'discovery']
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE name = 'subfinder' AND tenant_id IS NULL);

-- DNSX - DNS resolution
INSERT INTO tools (tenant_id, name, display_name, description, capabilities, install_method, is_active, is_builtin, tags)
SELECT NULL, 'dnsx', 'DNSX', 'DNS resolution and record enumeration toolkit',
       ARRAY['recon', 'dns'], 'go', true, true, ARRAY['recon', 'dns', 'resolution']
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE name = 'dnsx' AND tenant_id IS NULL);

-- Naabu - Port scanning
INSERT INTO tools (tenant_id, name, display_name, description, capabilities, install_method, is_active, is_builtin, tags)
SELECT NULL, 'naabu', 'Naabu', 'Fast SYN/CONNECT port scanner',
       ARRAY['recon', 'portscan'], 'go', true, true, ARRAY['recon', 'portscan', 'network']
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE name = 'naabu' AND tenant_id IS NULL);

-- HTTPX - HTTP probing
INSERT INTO tools (tenant_id, name, display_name, description, capabilities, install_method, is_active, is_builtin, tags)
SELECT NULL, 'httpx', 'HTTPX', 'HTTP probing and technology fingerprinting',
       ARRAY['recon', 'http', 'tech_detect'], 'go', true, true, ARRAY['recon', 'http', 'fingerprint']
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE name = 'httpx' AND tenant_id IS NULL);

-- Katana - URL crawling
INSERT INTO tools (tenant_id, name, display_name, description, capabilities, install_method, is_active, is_builtin, tags)
SELECT NULL, 'katana', 'Katana', 'Web crawler for endpoint and URL discovery',
       ARRAY['recon', 'crawler', 'url_discovery'], 'go', true, true, ARRAY['recon', 'crawler', 'spider']
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE name = 'katana' AND tenant_id IS NULL);

-- =============================================================================
-- 7. Link ALL Built-in Tools to Capabilities via Junction Table
-- =============================================================================
-- Links both the 10 core tools (from 000015) and 5 recon tools (above)
-- to their capabilities via the junction table.
INSERT INTO tool_capabilities (tool_id, capability_id)
SELECT t.id, c.id
FROM tools t
CROSS JOIN LATERAL unnest(t.capabilities) AS cap_name
JOIN capabilities c ON c.name = cap_name AND c.tenant_id IS NULL
WHERE t.tenant_id IS NULL
  AND t.is_builtin = TRUE
  AND t.capabilities IS NOT NULL
  AND array_length(t.capabilities, 1) > 0
ON CONFLICT (tool_id, capability_id) DO NOTHING;
