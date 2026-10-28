-- The dnsx-enum tool row: subdomain brute force with dnsx (capability
-- enumerate.subdomains@1, active, tier 1). Sensors from v0.28 report it; the
-- row lets the platform keep it in a sensor's report (an unknown tool is
-- dropped and shown as ignored on the sensor's manifest), lets tenants see
-- and enable it, and shows which sensors have it. It needs a label list (a
-- wordlist content slot "labels") from the platform's content; a job without
-- one is refused by the sensor. Built-in rows are platform data (tenant_id
-- NULL). An existing platform dnsx-enum row is left alone. output_types is empty
-- like every tool the stage catalog does not list yet (a test keeps the two equal);
-- wiring enumerate.subdomains@1 into the planner is a separate change.
INSERT INTO tools (id, tenant_id, name, display_name, description, category_id, install_method,
                   config_schema, default_config, capabilities, supported_targets, output_formats,
                   docs_url, github_url, is_active, is_builtin, tags, metadata, output_types)
SELECT '00000000-0000-0000-0000-000000000135', NULL, 'dnsx-enum', 'dnsx brute force',
       'Subdomain brute force of a root domain with a label list (wordlist) from the platform, through the sensor resolvers; active (sends DNS queries toward the target name servers). Only names that resolve are reported.',
       '00000000-0000-0000-0000-000000000207', 'binary',
       '{}', '{}', '{recon,subdomain}', '{domain}', '{json}',
       NULL, 'https://github.com/projectdiscovery/dnsx', true, true, '{recon,subdomain,active,bruteforce}', '{}', '{}'
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE tenant_id IS NULL AND name = 'dnsx-enum');
