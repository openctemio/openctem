-- The codeql tool row (RFC-055, D9).
--
-- The sensor ships codeql and the scan-stage catalog routes sast.code to it,
-- but no tools row existed, so tenants could not enable it or see whether
-- their sensors have it. Built-in rows are platform data (tenant_id NULL).
-- An existing platform codeql row is left alone.
INSERT INTO tools (id, tenant_id, name, display_name, description, category_id, install_method,
                   config_schema, default_config, capabilities, supported_targets, output_formats,
                   is_active, is_builtin, tags, metadata, output_types)
SELECT '00000000-0000-0000-0000-000000000131', NULL, 'codeql', 'CodeQL',
       'Semantic code analysis with CodeQL query packs', '00000000-0000-0000-0000-000000000201', 'binary',
       '{}', '{}', '{sast,security_analysis}', '{file,repository}', '{sarif}',
       true, true, '{}', '{}', '{}'
WHERE NOT EXISTS (SELECT 1 FROM tools WHERE tenant_id IS NULL AND name = 'codeql');
