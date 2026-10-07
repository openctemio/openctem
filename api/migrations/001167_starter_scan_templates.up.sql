-- Starter scan workflows (research note on the scan workflow designer, §3.7):
-- Discover, Discover + Vuln, Web app, Network and Code / CI.
--
-- They are system templates built from capability steps: each step names a
-- catalog capability and no tool, so the platform picks an available
-- implementation (the catalog default first). Like every system template
-- they are read-only and copied into a tenant on use; a tenant edits its
-- copy. Every step graph passes the workflow graph check.
--
-- The seeded presets they replace (Subdomain Enumeration, Port Scanning,
-- Full Reconnaissance, Continuous Monitoring and the two inactive web/API
-- presets, which named tools outside the catalog) are deactivated, not
-- deleted: scans and tenant copies made from them keep working. The Quick
-- Scan template is unchanged.

INSERT INTO pipeline_templates (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'Discover', 'Find the subdomains of your root domains, resolve them and probe their web services. Passive discovery and DNS (T0), then HTTP probing (T1) of the names the scope allows.', 1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}', true, true, '{starter,discovery,easm}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0001-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000001', 'subdomains', 'Subdomain discovery', 'Any tool that runs discover.subdomains; the platform picks an available one.', 1, '{discover.subdomains}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0001-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000001', 'dns', 'DNS resolution', 'Any tool that runs resolve.dns; the platform picks an available one.', 2, '{resolve.dns}', '{}', 3600, '{subdomains}', 'always', 1, 60, 400, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0001-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000001', 'http', 'HTTP probe', 'Any tool that runs probe.http; the platform picks an available one.', 3, '{probe.http}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_templates (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'Discover + Vuln', 'Discover subdomains, resolve them, scan their ports, probe the web services and run non-intrusive vulnerability templates on the web services and open ports.', 1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}', true, true, '{starter,discovery,vulnerability,easm}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0002-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000002', 'subdomains', 'Subdomain discovery', 'Any tool that runs discover.subdomains; the platform picks an available one.', 1, '{discover.subdomains}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0002-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000002', 'dns', 'DNS resolution', 'Any tool that runs resolve.dns; the platform picks an available one.', 2, '{resolve.dns}', '{}', 3600, '{subdomains}', 'always', 1, 60, 400, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0002-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000002', 'ports', 'Port scan', 'Any tool that runs scan.ports; the platform picks an available one.', 3, '{scan.ports}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 40)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0002-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000002', 'http', 'HTTP probe', 'Any tool that runs probe.http; the platform picks an available one.', 4, '{probe.http}', '{}', 3600, '{dns,ports}', 'always', 1, 60, 1000, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0002-0000-0000-000000000005', 'a0000002-0000-0000-0000-000000000002', 'vulns', 'Vulnerability templates', 'Any tool that runs vuln.templates; the platform picks an available one.', 5, '{vuln.templates}', '{}', 3600, '{http,ports}', 'always', 1, 60, 1300, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_templates (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000000', 'Web app', 'Probe web applications, crawl them on the same host and run non-intrusive vulnerability templates on what was found.', 1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}', true, true, '{starter,web,vulnerability}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0003-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000003', 'http', 'HTTP probe', 'Any tool that runs probe.http; the platform picks an available one.', 1, '{probe.http}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0003-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000003', 'crawl', 'Web crawl', 'Any tool that runs crawl.web; the platform picks an available one.', 2, '{crawl.web}', '{}', 3600, '{http}', 'always', 1, 60, 400, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0003-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000003', 'vulns', 'Vulnerability templates', 'Any tool that runs vuln.templates; the platform picks an available one.', 3, '{vuln.templates}', '{}', 3600, '{http,crawl}', 'always', 1, 60, 700, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_templates (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000000', 'Network', 'Scan addresses and hosts for open ports, probe the web services and run non-intrusive vulnerability templates on the services found.', 1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}', true, true, '{starter,network,vulnerability}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0004-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000004', 'ports', 'Port scan', 'Any tool that runs scan.ports; the platform picks an available one.', 1, '{scan.ports}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0004-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000004', 'http', 'HTTP probe', 'Any tool that runs probe.http; the platform picks an available one.', 2, '{probe.http}', '{}', 3600, '{ports}', 'always', 1, 60, 400, 40)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0004-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000004', 'vulns', 'Vulnerability templates', 'Any tool that runs vuln.templates; the platform picks an available one.', 3, '{vuln.templates}', '{}', 3600, '{ports,http}', 'always', 1, 60, 700, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_templates (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000000', 'Code / CI', 'Scan repositories for committed secrets, code flaws, vulnerable dependencies and infrastructure-as-code misconfigurations. Static analysis only (T0).', 1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}', true, true, '{starter,code,ci}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0005-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000005', 'secrets', 'Secrets in code', 'Any tool that runs secrets.code; the platform picks an available one.', 1, '{secrets.code}', '{}', 3600, '{}', 'always', 1, 60, 100, 40)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0005-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000005', 'sast', 'Static analysis', 'Any tool that runs sast.code; the platform picks an available one.', 2, '{sast.code}', '{}', 3600, '{}', 'always', 1, 60, 100, 160)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0005-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000005', 'deps', 'Dependency scan', 'Any tool that runs sca.deps; the platform picks an available one.', 3, '{sca.deps}', '{}', 3600, '{}', 'always', 1, 60, 100, 280)
ON CONFLICT (id) DO NOTHING;

INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0005-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000005', 'iac', 'IaC misconfiguration', 'Any tool that runs iac.misconfig; the platform picks an available one.', 4, '{iac.misconfig}', '{}', 3600, '{}', 'always', 1, 60, 100, 400)
ON CONFLICT (id) DO NOTHING;

UPDATE pipeline_templates SET is_active = false, updated_at = now()
WHERE is_system_template AND id IN ('a0000001-0000-0000-0000-000000000001', 'a0000001-0000-0000-0000-000000000002', 'a0000001-0000-0000-0000-000000000003', 'a0000001-0000-0000-0000-000000000004', 'a0000001-0000-0000-0000-000000000005', 'a0000001-0000-0000-0000-000000000006');
