-- Passive discovery starter workflows (docs/rfcs/RFC-071-scan-intensity.md).
--
-- Passive discovery: subdomains from passive sources (certificate
-- transparency among them) and DNS resolution through recursive resolvers.
-- Every step is T0: nothing is sent to the target hosts, so a passive scan
-- can run it. Names it finds go through the normal ingest, attribution and
-- review queue.
--
-- Probe new assets: port scan and HTTP probe (T1) with no discovery step,
-- for the active half of continuous discovery: a scan of *.<root> with
-- target_options.new_since_last_run probes only the assets that came into
-- scope since its previous successful run.
--
-- System templates, read-only, copied into a tenant on use, like the other
-- starters (migration 001201). Capability steps name no tool: the platform
-- picks an available implementation.

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000000', 'Passive discovery',
        'Find the subdomains of your root domains from passive sources (certificate transparency, passive DNS) and resolve them through recursive resolvers. Nothing is sent to your hosts (T0). New names go to the review queue.',
        1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}',
        true, true, '{starter,discovery,passive,easm}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0006-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000006', 'subdomains', 'Subdomain discovery', 'Any tool that runs discover.subdomains from passive sources; the platform picks an available one.', 1, '{discover.subdomains}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0006-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000006', 'dns', 'DNS resolution', 'Any tool that runs resolve.dns through recursive resolvers; the platform picks an available one.', 2, '{resolve.dns}', '{}', 3600, '{subdomains}', 'always', 1, 60, 400, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES ('a0000002-0000-0000-0000-000000000007', '00000000-0000-0000-0000-000000000000', 'Probe new assets',
        'Scan the ports and probe the web services of the assets a scan selects, with no discovery step (T1). With "only assets new since the last run" on a *.example.com target, it probes only what came into scope since the previous run.',
        1, '[{"type": "manual"}, {"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 14400, "notify_on_failure": true, "max_parallel_steps": 3}',
        true, true, '{starter,discovery,continuous,easm}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0007-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000007', 'ports', 'Port scan', 'Any tool that runs scan.ports; the platform picks an available one.', 1, '{scan.ports}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0007-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000007', 'http', 'HTTP probe', 'Any tool that runs probe.http; the platform picks an available one.', 2, '{probe.http}', '{}', 3600, '{}', 'always', 1, 60, 100, 280)
ON CONFLICT (id) DO NOTHING;
