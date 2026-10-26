-- EASM workflow depth and the built-in recon workflows
-- (docs/architecture/scan-stages.md §1.3 and §1.5).
--
-- scans.depth: how much of its workflow each run of a scan executes
-- (passive, standard or deep). Existing scans get standard, which runs every
-- step as before: a step without a run policy reacts to no depth except
-- passive, which no existing scan has.
--
-- scan_workflow_steps.run_policy: per step, the depth it starts at, the
-- standard params and target cap it uses at each depth, and whether it waits
-- for a tool (optional). '{}' (every existing step) changes nothing.
--
-- The EASM recon set (system workflows, read-only, copied into a tenant on
-- use, like the other starters): Passive discovery (existing, now with
-- depth params), Subdomains, Standard recon, Web and Deep recon. Steps name
-- capabilities and no tool. Steps whose capability has no tool yet
-- (screenshots, service detection, takeover check) are optional: the run
-- skips them with the reason until a tool that implements them is
-- installed. Each workflow turns on delta gating and continue-on-failure.
--
-- Discover, Discover + Vuln and Web app are superseded by Subdomains,
-- Standard recon and Web: deactivated, not deleted, so scans and tenant
-- copies made from them keep working.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS depth VARCHAR(16) NOT NULL DEFAULT 'standard';
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_depth;
ALTER TABLE scans ADD CONSTRAINT chk_scans_depth CHECK (depth IN ('passive', 'standard', 'deep'));
COMMENT ON COLUMN scans.depth IS 'How much of its workflow each run executes: passive (only steps that send nothing to the targets), standard or deep';

ALTER TABLE scan_workflow_steps ADD COLUMN IF NOT EXISTS run_policy JSONB NOT NULL DEFAULT '{}'::jsonb;
UPDATE scan_workflows SET is_active = true, updated_at = now()
WHERE id IN ('a0000002-0000-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000003');
UPDATE scan_workflows
SET settings = settings - 'delta_gating' - 'continue_on_failed_dependency',
    tags = array_remove(tags, 'easm-recon'),
    version = GREATEST(version - 1, 1), updated_at = now()
WHERE id = 'a0000002-0000-0000-0000-000000000006';

ALTER TABLE scan_workflow_steps DROP CONSTRAINT IF EXISTS chk_scan_workflow_steps_run_policy;
ALTER TABLE scan_workflow_steps ADD CONSTRAINT chk_scan_workflow_steps_run_policy CHECK (jsonb_typeof(run_policy) = 'object');
COMMENT ON COLUMN scan_workflow_steps.run_policy IS 'Step run policy: min_depth, per-depth standard params and target cap, optional (waits for a tool)';

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000012', '00000000-0000-0000-0000-000000000000', 'Subdomains',
        'Discover subdomains, resolve them with the wildcard filter and probe which ones serve the web. A takeover check runs when a tool for it is installed (the platform''s daily DNS check already flags dangling records). Passive stops after resolution.',
        1, '[{"type": "manual"}, {"type": "api"}]', '{"continue_on_failed_dependency": true, "delta_gating": true, "fail_fast": false, "max_parallel_steps": 4, "notify_on_failure": true, "timeout_seconds": 14400}',
        true, true, '{starter,easm,easm-recon,discovery}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0012-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000012', 'subdomains', 'Subdomain discovery', 'Any tool that runs discover.subdomains; the platform picks an available one.', 1, '{discover.subdomains}', '{}', 3600, '{}', 'always', 1, 60, 100, 120, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0012-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000012', 'dns', 'DNS resolution', 'Any tool that runs resolve.dns; the platform picks an available one.', 2, '{resolve.dns}', '{}', 3600, '{subdomains}', 'always', 1, 60, 400, 120, '{"depths": {"deep": {"params": {"record_types": ["a", "aaaa", "cname", "mx", "ns", "txt"], "wildcard_filter": true}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0012-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000012', 'http', 'Web probe', 'Any tool that runs probe.http; the platform picks an available one.', 3, '{probe.http}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 120, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0012-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000012', 'takeover', 'Takeover check', 'Runs when a tool that implements check.takeover is installed; until then the run skips it with the reason.', 4, '{check.takeover}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 280, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000013', '00000000-0000-0000-0000-000000000000', 'Standard recon',
        'The standard external recon chain: discovery, resolution with the wildcard filter, web probe, port scan and network lookups in parallel, then screenshots and service detection when their tools are installed, and vulnerability templates on the web services. Heavy steps run only on assets that are new, changed or due since the last run. Deep adds a crawl that feeds the templates, more ports and lower severities.',
        1, '[{"type": "manual"}, {"type": "api"}]', '{"continue_on_failed_dependency": true, "delta_gating": true, "fail_fast": false, "max_parallel_steps": 4, "notify_on_failure": true, "timeout_seconds": 14400}',
        true, true, '{starter,easm,easm-recon,vulnerability}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000013', 'subdomains', 'Subdomain discovery', 'Any tool that runs discover.subdomains; the platform picks an available one.', 1, '{discover.subdomains}', '{}', 3600, '{}', 'always', 1, 60, 100, 200, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000013', 'dns', 'DNS resolution', 'Any tool that runs resolve.dns; the platform picks an available one.', 2, '{resolve.dns}', '{}', 3600, '{subdomains}', 'always', 1, 60, 400, 200, '{"depths": {"deep": {"params": {"record_types": ["a", "aaaa", "cname", "mx", "ns", "txt"], "wildcard_filter": true}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000013', 'http', 'Web probe', 'Any tool that runs probe.http; the platform picks an available one.', 3, '{probe.http}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 60, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000013', 'ports', 'Port scan', 'Any tool that runs scan.ports; the platform picks an available one.', 4, '{scan.ports}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 200, '{"depths": {"deep": {"max_targets": 5000, "params": {"top_n": 1000}}, "standard": {"max_targets": 1000, "params": {"top_n": 100}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000005', 'a0000002-0000-0000-0000-000000000013', 'asn', 'Networks of the addresses', 'Any tool that runs lookup.asn; the platform picks an available one.', 5, '{lookup.asn}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 340, '{"depths": {"deep": {"params": {"include_announced": true}}, "passive": {"params": {"include_announced": false}}, "standard": {"params": {"include_announced": true}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000006', 'a0000002-0000-0000-0000-000000000013', 'screenshots', 'Screenshots', 'Runs when a tool that implements capture.screenshot is installed; until then the run skips it with the reason.', 6, '{capture.screenshot}', '{}', 3600, '{http}', 'always', 1, 60, 1000, 0, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000007', 'a0000002-0000-0000-0000-000000000013', 'crawl', 'Crawl', 'Any tool that runs crawl.web; the platform picks an available one.', 7, '{crawl.web}', '{}', 3600, '{http}', 'always', 1, 60, 1000, 120, '{"depths": {"deep": {"max_targets": 200}, "standard": {"max_targets": 100}}, "min_depth": "deep"}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000008', 'a0000002-0000-0000-0000-000000000013', 'services', 'Service detection', 'Runs when a tool that implements detect.services is installed; until then the run skips it with the reason.', 8, '{detect.services}', '{}', 3600, '{ports}', 'always', 1, 60, 1000, 260, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0013-0000-0000-000000000009', 'a0000002-0000-0000-0000-000000000013', 'templates', 'Vulnerability templates', 'Any tool that runs vuln.templates; the platform picks an available one.', 9, '{vuln.templates}', '{}', 3600, '{http,crawl}', 'always', 1, 60, 1300, 60, '{"depths": {"deep": {"max_targets": 2000, "params": {"severity": ["critical", "high", "medium", "low"]}}, "standard": {"max_targets": 500, "params": {"severity": ["critical", "high", "medium"]}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000014', '00000000-0000-0000-0000-000000000000', 'Web',
        'Start from a list of web addresses or names: probe them, take screenshots when the tool is installed and run vulnerability templates on the web services that are new, changed or due. Deep adds a crawl that feeds the templates. Needs Standard depth or deeper.',
        1, '[{"type": "manual"}, {"type": "api"}]', '{"continue_on_failed_dependency": true, "delta_gating": true, "fail_fast": false, "max_parallel_steps": 4, "notify_on_failure": true, "timeout_seconds": 14400}',
        true, true, '{starter,easm,easm-recon,web}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0014-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000014', 'http', 'Web probe', 'Any tool that runs probe.http; the platform picks an available one.', 1, '{probe.http}', '{}', 3600, '{}', 'always', 1, 60, 100, 120, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0014-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000014', 'screenshots', 'Screenshots', 'Runs when a tool that implements capture.screenshot is installed; until then the run skips it with the reason.', 2, '{capture.screenshot}', '{}', 3600, '{http}', 'always', 1, 60, 400, 0, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0014-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000014', 'crawl', 'Crawl', 'Any tool that runs crawl.web; the platform picks an available one.', 3, '{crawl.web}', '{}', 3600, '{http}', 'always', 1, 60, 400, 120, '{"depths": {"deep": {"max_targets": 200}, "standard": {"max_targets": 100}}, "min_depth": "deep"}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0014-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000014', 'templates', 'Vulnerability templates', 'Any tool that runs vuln.templates; the platform picks an available one.', 4, '{vuln.templates}', '{}', 3600, '{http,crawl}', 'always', 1, 60, 700, 120, '{"depths": {"deep": {"max_targets": 2000, "params": {"severity": ["critical", "high", "medium", "low"]}}, "standard": {"max_targets": 500, "params": {"severity": ["critical", "high", "medium"]}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000015', '00000000-0000-0000-0000-000000000000', 'Deep recon',
        'Everything in Standard recon plus registration data, a takeover check when its tool is installed and a crawl at every active depth, with higher caps. Subdomain permutations and recursion join this workflow when a tool for them is installed. Best for onboarding a new root domain.',
        1, '[{"type": "manual"}, {"type": "api"}]', '{"continue_on_failed_dependency": true, "delta_gating": true, "fail_fast": false, "max_parallel_steps": 4, "notify_on_failure": true, "timeout_seconds": 28800}',
        true, true, '{starter,easm,easm-recon,deep}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000015', 'subdomains', 'Subdomain discovery', 'Any tool that runs discover.subdomains; the platform picks an available one.', 1, '{discover.subdomains}', '{}', 3600, '{}', 'always', 1, 60, 100, 200, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000015', 'rdap', 'Registration data', 'Any tool that runs lookup.rdap; the platform picks an available one.', 2, '{lookup.rdap}', '{}', 3600, '{}', 'always', 1, 60, 100, 360, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000015', 'dns', 'DNS resolution', 'Any tool that runs resolve.dns; the platform picks an available one.', 3, '{resolve.dns}', '{}', 3600, '{subdomains}', 'always', 1, 60, 400, 200, '{"depths": {"deep": {"params": {"record_types": ["a", "aaaa", "cname", "mx", "ns", "txt"], "wildcard_filter": true}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000015', 'http', 'Web probe', 'Any tool that runs probe.http; the platform picks an available one.', 4, '{probe.http}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 60, '{}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000005', 'a0000002-0000-0000-0000-000000000015', 'ports', 'Port scan', 'Any tool that runs scan.ports; the platform picks an available one.', 5, '{scan.ports}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 200, '{"depths": {"deep": {"max_targets": 10000, "params": {"top_n": 1000}}, "standard": {"max_targets": 2000, "params": {"top_n": 100}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000006', 'a0000002-0000-0000-0000-000000000015', 'asn', 'Networks of the addresses', 'Any tool that runs lookup.asn; the platform picks an available one.', 6, '{lookup.asn}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 340, '{"depths": {"deep": {"params": {"include_announced": true}}, "passive": {"params": {"include_announced": false}}, "standard": {"params": {"include_announced": true}}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000007', 'a0000002-0000-0000-0000-000000000015', 'takeover', 'Takeover check', 'Runs when a tool that implements check.takeover is installed; until then the run skips it with the reason.', 7, '{check.takeover}', '{}', 3600, '{dns}', 'always', 1, 60, 700, 480, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000008', 'a0000002-0000-0000-0000-000000000015', 'screenshots', 'Screenshots', 'Runs when a tool that implements capture.screenshot is installed; until then the run skips it with the reason.', 8, '{capture.screenshot}', '{}', 3600, '{http}', 'always', 1, 60, 1000, 0, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000009', 'a0000002-0000-0000-0000-000000000015', 'crawl', 'Crawl', 'Any tool that runs crawl.web; the platform picks an available one.', 9, '{crawl.web}', '{}', 3600, '{http}', 'always', 1, 60, 1000, 120, '{"depths": {"deep": {"max_targets": 200}, "standard": {"max_targets": 100}}}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000010', 'a0000002-0000-0000-0000-000000000015', 'services', 'Service detection', 'Runs when a tool that implements detect.services is installed; until then the run skips it with the reason.', 10, '{detect.services}', '{}', 3600, '{ports}', 'always', 1, 60, 1000, 260, '{"optional": true}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
VALUES ('b0000002-0015-0000-0000-000000000011', 'a0000002-0000-0000-0000-000000000015', 'templates', 'Vulnerability templates', 'Any tool that runs vuln.templates; the platform picks an available one.', 11, '{vuln.templates}', '{}', 3600, '{http,crawl}', 'always', 1, 60, 1300, 60, '{"depths": {"deep": {"max_targets": 5000, "params": {"severity": ["critical", "high", "medium", "low"]}}, "standard": {"max_targets": 1000, "params": {"severity": ["critical", "high", "medium"]}}}}')
ON CONFLICT (id) DO NOTHING;

-- Passive discovery joins the recon set: every DNS record type at Deep,
-- announced ranges from Standard up.
UPDATE scan_workflow_steps SET run_policy = '{"depths": {"deep": {"params": {"record_types": ["a", "aaaa", "cname", "mx", "ns", "txt"], "wildcard_filter": true}}}}'
WHERE scan_workflow_id = 'a0000002-0000-0000-0000-000000000006' AND step_key = 'dns';
UPDATE scan_workflow_steps SET run_policy = '{"depths": {"deep": {"params": {"include_announced": true}}, "passive": {"params": {"include_announced": false}}, "standard": {"params": {"include_announced": true}}}}'
WHERE scan_workflow_id = 'a0000002-0000-0000-0000-000000000006' AND step_key = 'asn';
UPDATE scan_workflows
SET settings = settings || '{"delta_gating": true, "continue_on_failed_dependency": true}'::jsonb,
    tags = CASE WHEN 'easm-recon' = ANY(tags) THEN tags ELSE array_append(tags, 'easm-recon') END,
    version = version + 1, updated_at = now()
WHERE id = 'a0000002-0000-0000-0000-000000000006';

UPDATE scan_workflows SET is_active = false, updated_at = now()
WHERE id IN ('a0000002-0000-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000003');
