-- The opengrep tool row: the sast.code engine that runs local rules only
-- (research/132). Sensors from the release with the -opengrep image report
-- it; the row lets tenants enable it and see which sensors have it.
-- Built-in rows are platform data (tenant_id NULL). An existing platform
-- opengrep row is left alone.
INSERT INTO tools (id, tenant_id, name, display_name, description, category_id, install_method,
                   config_schema, default_config, capabilities, supported_targets, output_formats,
                   docs_url, github_url, is_active, is_builtin, tags, metadata, output_types)
SELECT '00000000-0000-0000-0000-000000000134', NULL, 'opengrep', 'Opengrep',
       'Static analysis with local rules (the managed rules pack or custom rules); never fetches rules',
       '00000000-0000-0000-0000-000000000201', 'binary',
       '{}', '{}', '{sast,security_analysis}', '{file,repository}', '{json,sarif}',
       NULL, 'https://github.com/opengrep/opengrep', true, true, '{sast}', '{}', '{}'
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE tenant_id IS NULL AND name = 'opengrep');
