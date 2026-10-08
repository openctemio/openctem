-- The legacy system templates (Subdomain Enumeration, Port Scanning, Full
-- Reconnaissance, Web Vulnerability Scan, API Security Testing, Continuous
-- Monitoring; ids a0000001-*) pinned a tool on every step, some of them
-- tools the catalog does not have (dalfox, sqlmap, kiterunner, ffuf) or no
-- tool at all, and stored tool-native settings ("top_ports": "1000").
-- A copy made from one failed to save on a tenant without those tools.
--
-- Their steps become capability steps with "Any tool", like the starter
-- templates: each step names its catalog capability and no tool, so the
-- platform picks an available implementation. Steps with no catalog
-- capability are removed (their dependents no longer wait for them), and
-- the settings keep only the capability's standard params. Only system
-- templates change: tenant copies are the tenant's data and are fixed in
-- the editor. The rows as they were are kept for the down migration.

CREATE TABLE legacy_template_steps_backup_001322 AS
SELECT s.*
FROM scan_workflow_steps s
JOIN scan_workflows w ON w.id = s.scan_workflow_id
WHERE w.is_system_template AND w.id::text LIKE 'a0000001-%';

CREATE TABLE legacy_templates_backup_001322 AS
SELECT id, description
FROM scan_workflows
WHERE is_system_template AND id::text LIKE 'a0000001-%';

-- Steps no catalog capability runs.
DELETE FROM scan_workflow_steps s
USING scan_workflows w
WHERE w.id = s.scan_workflow_id
  AND w.is_system_template AND w.id::text LIKE 'a0000001-%'
  AND coalesce(s.tool, '') NOT IN ('subfinder', 'dnsx', 'naabu', 'httpx', 'katana', 'nuclei');

-- Nothing waits for a removed step.
UPDATE scan_workflow_steps s
SET depends_on = ARRAY(
    SELECT d FROM unnest(s.depends_on) AS d
    WHERE d IN (SELECT x.step_key FROM scan_workflow_steps x WHERE x.scan_workflow_id = s.scan_workflow_id)
)
FROM scan_workflows w
WHERE w.id = s.scan_workflow_id
  AND w.is_system_template AND w.id::text LIKE 'a0000001-%';

-- Capability steps with any tool, standard params only.
UPDATE scan_workflow_steps s
SET capabilities = ARRAY[
        CASE s.tool
            WHEN 'subfinder' THEN 'discover.subdomains'
            WHEN 'dnsx' THEN 'resolve.dns'
            WHEN 'naabu' THEN 'scan.ports'
            WHEN 'httpx' THEN 'probe.http'
            WHEN 'katana' THEN 'crawl.web'
            WHEN 'nuclei' THEN 'vuln.templates'
        END],
    config = CASE s.tool
        WHEN 'naabu' THEN jsonb_strip_nulls(jsonb_build_object(
            'ports', s.config->>'ports',
            'top_n', CASE WHEN s.config->>'top_ports' ~ '^[0-9]{1,5}$' THEN (s.config->>'top_ports')::int END))
        WHEN 'nuclei' THEN jsonb_strip_nulls(jsonb_build_object(
            'severity', CASE WHEN jsonb_typeof(s.config->'severity') = 'array' THEN s.config->'severity' END))
        ELSE '{}'::jsonb
    END,
    description = 'Any tool that runs ' ||
        CASE s.tool
            WHEN 'subfinder' THEN 'discover.subdomains'
            WHEN 'dnsx' THEN 'resolve.dns'
            WHEN 'naabu' THEN 'scan.ports'
            WHEN 'httpx' THEN 'probe.http'
            WHEN 'katana' THEN 'crawl.web'
            WHEN 'nuclei' THEN 'vuln.templates'
        END || '; the platform picks an available one.',
    tool = NULL,
    tool_id = NULL,
    prefer_tools = '{}'
FROM scan_workflows w
WHERE w.id = s.scan_workflow_id
  AND w.is_system_template AND w.id::text LIKE 'a0000001-%';

UPDATE scan_workflows SET description = CASE id::text
    WHEN 'a0000001-0000-0000-0000-000000000001' THEN 'Passive subdomain discovery, then DNS resolution of the results.'
    WHEN 'a0000001-0000-0000-0000-000000000002' THEN 'Fast port discovery, then a full port scan.'
    WHEN 'a0000001-0000-0000-0000-000000000003' THEN 'Subdomain discovery, then HTTP probing and port discovery in parallel, then vulnerability templates.'
    WHEN 'a0000001-0000-0000-0000-000000000004' THEN 'Crawl web applications, then run vulnerability templates on what was found.'
    WHEN 'a0000001-0000-0000-0000-000000000005' THEN 'Vulnerability templates for API exposures.'
    WHEN 'a0000001-0000-0000-0000-000000000006' THEN 'DNS, port and HTTP checks of known assets.'
    ELSE description END
WHERE is_system_template AND id::text LIKE 'a0000001-%';
