-- A retired system workflow names the template that replaces it, so the UI can
-- say why it is gone instead of showing an unexplained "Unavailable".
-- A system workflow is retired when it is inactive; scans and tenant copies made
-- from it keep working. NULL means retired with no direct replacement.

ALTER TABLE scan_workflows
    ADD COLUMN IF NOT EXISTS superseded_by UUID REFERENCES scan_workflows(id) ON DELETE SET NULL;
COMMENT ON COLUMN scan_workflows.superseded_by IS 'For a retired system workflow: the system workflow that replaces it';

-- Discover, Discover + Vuln, Web app -> Subdomains, Standard recon, Web.
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000012' WHERE id = 'a0000002-0000-0000-0000-000000000001' AND is_system_template;
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000013' WHERE id = 'a0000002-0000-0000-0000-000000000002' AND is_system_template;
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000014' WHERE id = 'a0000002-0000-0000-0000-000000000003' AND is_system_template;
-- The older presets: Subdomain Enumeration, Port Scanning, Full Reconnaissance, Web Vulnerability Scan.
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000012' WHERE id = 'a0000001-0000-0000-0000-000000000001' AND is_system_template;
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000004' WHERE id = 'a0000001-0000-0000-0000-000000000002' AND is_system_template;
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000013' WHERE id = 'a0000001-0000-0000-0000-000000000003' AND is_system_template;
UPDATE scan_workflows SET superseded_by = 'a0000002-0000-0000-0000-000000000014' WHERE id = 'a0000001-0000-0000-0000-000000000004' AND is_system_template;
