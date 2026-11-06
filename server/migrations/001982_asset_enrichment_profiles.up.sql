-- Built-in passive enrichment profiles (docs/rfcs/RFC-075-asset-freshness.md
-- §5.4): system workflows the asset-enrichment controller runs, one per asset
-- type, built only from T0 capability steps so any available implementation
-- runs them and nothing is sent to the target hosts.
--
--   Enrich root domains: resolve.dns and lookup.rdap
--   Enrich host names:   resolve.dns
--   Enrich addresses:    lookup.asn
--
-- Read-only system templates (tenant_id = system), tagged enrichment and not
-- starter, so the New Scan wizard does not offer them first.
--
-- Live impact: three template rows and four step rows.

INSERT INTO scan_workflows (id, tenant_id, name, description, version, triggers, settings, is_active, is_system_template, tags)
VALUES
 ('a0000003-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'Enrich root domains',
  'Automatic enrichment of a new root domain: DNS records through recursive resolvers and registration data (RDAP). Nothing is sent to your hosts (T0).',
  1, '[{"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 3600, "notify_on_failure": false, "max_parallel_steps": 2}',
  true, true, '{enrichment,passive,easm}'),
 ('a0000003-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'Enrich host names',
  'Automatic enrichment of a new host name: DNS records through recursive resolvers. Addresses it finds are enriched in turn. Nothing is sent to your hosts (T0).',
  1, '[{"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 3600, "notify_on_failure": false, "max_parallel_steps": 1}',
  true, true, '{enrichment,passive,easm}'),
 ('a0000003-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000000', 'Enrich addresses',
  'Automatic enrichment of a new address: origin autonomous system, holder and announced range from public routing data. Nothing is sent to your hosts (T0).',
  1, '[{"type": "api"}]', '{"fail_fast": false, "timeout_seconds": 3600, "notify_on_failure": false, "max_parallel_steps": 1}',
  true, true, '{enrichment,passive,easm}')
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES
 ('b0000003-0001-0000-0000-000000000001', 'a0000003-0000-0000-0000-000000000001', 'dns', 'DNS resolution',
  'Any tool that runs resolve.dns through recursive resolvers; the platform picks an available one.', 1, '{resolve.dns}', '{}', 1800, '{}', 'always', 1, 60, 100, 120),
 ('b0000003-0001-0000-0000-000000000002', 'a0000003-0000-0000-0000-000000000001', 'rdap', 'Domain registration lookup',
  'Any tool that runs lookup.rdap; the platform picks an available one.', 2, '{lookup.rdap}', '{}', 1800, '{}', 'always', 1, 60, 340, 120),
 ('b0000003-0002-0000-0000-000000000001', 'a0000003-0000-0000-0000-000000000002', 'dns', 'DNS resolution',
  'Any tool that runs resolve.dns through recursive resolvers; the platform picks an available one.', 1, '{resolve.dns}', '{}', 1800, '{}', 'always', 1, 60, 100, 120),
 ('b0000003-0003-0000-0000-000000000001', 'a0000003-0000-0000-0000-000000000003', 'asn', 'Network ownership lookup',
  'Any tool that runs lookup.asn from public routing data; the platform picks an available one.', 1, '{lookup.asn}', '{}', 1800, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;
