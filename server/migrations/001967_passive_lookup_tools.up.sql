-- Passive lookups in the Passive discovery starter workflow
-- (docs/rfcs/RFC-071-scan-intensity.md §7).
--
-- The sensor ships two T0 lookup tools: rdap (lookup.rdap: registrar,
-- registrant organization, name servers and dates of a root domain from its
-- registry's RDAP service) and asn (lookup.asn: origin autonomous system,
-- holder and announced range of an address, from the public-domain IPtoASN
-- dataset). Neither sends anything to the target hosts.
--
-- 1. Their platform tool rows (tenant_id NULL), so the planner can resolve
--    the capabilities to them and tenants can see and enable them. An
--    existing platform row of the same name is left alone.
-- 2. Two steps in the system template "Passive discovery": the RDAP lookup
--    of the root domains (beside subdomain discovery) and the ASN lookup of
--    the addresses DNS resolution found. Tenant copies made before this
--    migration keep their steps. Results go through the normal ingest; a
--    network found only by a lookup waits in the review queue.

INSERT INTO tools (id, tenant_id, name, display_name, description, category_id, install_method,
                   config_schema, default_config, capabilities, supported_targets, output_formats,
                   is_active, is_builtin, tags, metadata, output_types)
SELECT '00000000-0000-0000-0000-000000000132', NULL, 'rdap', 'RDAP lookup',
       'Domain registration lookup (registrar, registrant organization, name servers, dates) from the registry RDAP service; never contacts the target',
       '00000000-0000-0000-0000-000000000207', 'binary',
       '{}', '{}', '{recon}', '{domain}', '{json}',
       true, true, '{recon,passive,rdap,whois}', '{}', '{domain}'
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE tenant_id IS NULL AND name = 'rdap');

INSERT INTO tools (id, tenant_id, name, display_name, description, category_id, install_method,
                   config_schema, default_config, capabilities, supported_targets, output_formats,
                   is_active, is_builtin, tags, metadata, output_types)
SELECT '00000000-0000-0000-0000-000000000133', NULL, 'asn', 'ASN lookup',
       'Network ownership lookup (origin autonomous system, holder, announced range) from public routing data; never contacts the target',
       '00000000-0000-0000-0000-000000000207', 'binary',
       '{}', '{}', '{recon}', '{ip,cidr}', '{json}',
       true, true, '{recon,passive,asn}', '{}', '{ip_address,network}'
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE tenant_id IS NULL AND name = 'asn');

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0006-0000-0000-000000000003', 'a0000002-0000-0000-0000-000000000006', 'rdap', 'Domain registration lookup', 'Any tool that runs lookup.rdap: registrar, registrant organization and name servers of the root domains from their registry. The platform picks an available one.', 3, '{lookup.rdap}', '{}', 1800, '{}', 'always', 1, 60, 100, 280)
ON CONFLICT (id) DO NOTHING;

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0006-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000006', 'asn', 'Network ownership lookup', 'Any tool that runs lookup.asn: origin autonomous system and announced range of the resolved addresses, from public routing data. The platform picks an available one.', 4, '{lookup.asn}', '{}', 1800, '{dns}', 'always', 1, 60, 700, 120)
ON CONFLICT (id) DO NOTHING;

UPDATE scan_workflows
SET description = 'Find the subdomains of your root domains from passive sources (certificate transparency, passive DNS), resolve them through recursive resolvers, look up the registration of the roots (RDAP) and the network owner of the addresses (ASN). Nothing is sent to your hosts (T0). New names and networks go to the review queue.',
    version = 2
WHERE id = 'a0000002-0000-0000-0000-000000000006' AND version = 1;
