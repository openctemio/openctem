-- Asset collectors in the tool catalog.
--
-- A collector sensor (sensor type "collector", e.g. the OpenCTEM Asset
-- Collector, github.com/openctemio/asset-collector) reports one tool of kind
-- "collector" per source it pulls inventory from. The platform keeps only
-- reported tools whose name is in this catalog (sensor.KnownCapabilityNames),
-- so without these rows the collector's heartbeat and manifest lose every
-- tool. They are in the catalog but not scannable: metadata.kind = 'collector' makes
-- scan creation refuse them (tool.Tool.IsCollector), since a collector runs
-- on its own schedule and takes no dispatched scans.
--
-- Add-only and idempotent.

INSERT INTO tool_categories (id, name, display_name, description, icon, is_builtin, sort_order)
SELECT '00000000-0000-0000-0000-000000000209', 'inventory', 'Asset Collectors',
       'Collectors that pull asset inventory from an external system on their own schedule (not scanners)',
       'Database', TRUE, 9
WHERE NOT EXISTS (SELECT 1 FROM tool_categories WHERE name = 'inventory' AND tenant_id IS NULL);

INSERT INTO tools (id, name, display_name, description, category_id, capabilities, supported_targets,
                   output_formats, docs_url, github_url, is_active, is_builtin, tags, metadata)
SELECT v.id::uuid, v.name, v.display_name, v.description,
       (SELECT id FROM tool_categories WHERE name = 'inventory' AND tenant_id IS NULL),
       ARRAY[]::text[], ARRAY[]::text[], ARRAY['json'],
       'https://github.com/openctemio/asset-collector#collectors',
       'https://github.com/openctemio/asset-collector',
       TRUE, TRUE, ARRAY['inventory', 'collector'],
       '{"kind": "collector"}'::jsonb
FROM (VALUES
    ('00000000-0000-0000-0000-000000000112', 'gcp-dns',  'Google Cloud DNS',
     'Collects public DNS records (A, AAAA, CNAME) from Google Cloud DNS as domain assets'),
    ('00000000-0000-0000-0000-000000000113', 'vcenter',  'VMware vCenter',
     'Collects virtual machines and ESXi hosts from VMware vCenter as host assets'),
    ('00000000-0000-0000-0000-000000000114', 'ldap',     'LDAP / Active Directory',
     'Collects computer objects from LDAP or Active Directory as host assets'),
    ('00000000-0000-0000-0000-000000000115', 'splunk',   'Splunk',
     'Collects the hosts and network devices seen in Splunk indices as assets'),
    ('00000000-0000-0000-0000-000000000116', 'prtg',     'PRTG Network Monitor',
     'Collects monitored devices from PRTG Network Monitor as network assets')
) AS v(id, name, display_name, description)
WHERE NOT EXISTS (SELECT 1 FROM tools t WHERE t.name = v.name AND t.tenant_id IS NULL);
