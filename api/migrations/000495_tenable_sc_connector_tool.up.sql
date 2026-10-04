-- The Tenable.sc connector in the tool catalog
-- (docs/rfcs/RFC-047-tenable-sc-sensor-connector.md).
--
-- A sensor with the Tenable.sc connector configured reports the tool
-- "tenable_sc" in its heartbeat and manifest. The platform keeps only
-- reported tools whose name is in this catalog (sensor.KnownCapabilityNames),
-- and command routing only hands a command naming a tool to a sensor that
-- reported it, so without this row no connector_sync command could ever be
-- claimed. metadata.kind = 'connector' keeps it out of scans
-- (tool.Tool.IsConnector): connector commands come from the integration.
--
-- Add-only and idempotent; a same-named row created otherwise is left alone.

INSERT INTO tools (id, name, display_name, description, category_id, install_method, capabilities,
                   supported_targets, output_formats, docs_url, github_url, is_active, is_builtin, tags, metadata)
SELECT '00000000-0000-0000-0000-000000000495'::uuid, 'tenable_sc', 'Tenable Security Center',
       'Sensor connector to Tenable Security Center: pulls hosts, vulnerabilities and plugin metadata with credentials kept on the sensor',
       (SELECT id FROM tool_categories WHERE name = 'network' AND tenant_id IS NULL),
       'binary',
       ARRAY[]::text[], ARRAY[]::text[], ARRAY['json'],
       'https://github.com/openctemio/sensor/blob/main/docs/TENABLE_SC.md',
       'https://github.com/openctemio/sensor',
       TRUE, TRUE, ARRAY['connector', 'tenable', 'vulnerability'],
       '{"kind": "connector"}'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM tools t WHERE t.name = 'tenable_sc' AND t.tenant_id IS NULL);
