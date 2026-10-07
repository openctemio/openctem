-- Representative data of an installation BEFORE the agent → sensor rename
-- (schema at migration 000227). Used by TestSensorRenameUpgrade.
-- Fixed ids so the assertions can name them.

INSERT INTO tenants (id, name, slug) VALUES
    ('11111111-0000-0000-0000-000000000001', 'upgrade tenant', 'upgrade-tenant');
INSERT INTO users (id, email) VALUES
    ('11111111-0000-0000-0000-000000000002', 'upgrade@example.com');

-- A custom role and a group carrying agents:* grants; a permission set too.
INSERT INTO roles (id, tenant_id, slug, name) VALUES
    ('11111111-0000-0000-0000-000000000003', '11111111-0000-0000-0000-000000000001', 'sensor-operators', 'Sensor operators');
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('11111111-0000-0000-0000-000000000003', 'agents:read'),
    ('11111111-0000-0000-0000-000000000003', 'agents:commands:write'),
    ('11111111-0000-0000-0000-000000000003', 'findings:read');
INSERT INTO groups (id, tenant_id, name, slug) VALUES
    ('11111111-0000-0000-0000-000000000004', '11111111-0000-0000-0000-000000000001', 'ops', 'ops');
INSERT INTO group_permissions (group_id, permission_id, effect) VALUES
    ('11111111-0000-0000-0000-000000000004', 'agents:write', 'allow');
INSERT INTO permission_sets (id, tenant_id, name, slug) VALUES
    ('11111111-0000-0000-0000-000000000005', '11111111-0000-0000-0000-000000000001', 'sensor admin', 'sensor-admin');
INSERT INTO permission_set_items (permission_set_id, permission_id, modification_type) VALUES
    ('11111111-0000-0000-0000-000000000005', 'agents:delete', 'add');

-- An oct_ API key whose scopes name agents:* permissions.
INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, scopes) VALUES
    ('11111111-0000-0000-0000-000000000006', '11111111-0000-0000-0000-000000000001',
     '11111111-0000-0000-0000-000000000002', 'ci', 'hash-oct', 'oct_aaaa',
     ARRAY['agents:read', 'findings:read', 'agents:commands:read']);

-- A sensor ("agent"), its key, a command pinned to it, a scan with a preference.
INSERT INTO agents (id, tenant_id, name, type, api_key_hash, api_key_prefix, tools, execution_mode, status, health) VALUES
    ('11111111-0000-0000-0000-000000000007', '11111111-0000-0000-0000-000000000001',
     'scanner-01', 'worker', 'hash-rda', 'rda_aaaaaaaa', ARRAY['nuclei'], 'daemon', 'active', 'online');
INSERT INTO agent_api_keys (id, agent_id, name, key_hash, key_prefix, scopes) VALUES
    ('11111111-0000-0000-0000-000000000008', '11111111-0000-0000-0000-000000000007', 'default',
     'hash-rda-2', 'rda_bbbbbbbb', ARRAY['agent:heartbeat', 'agent:read', 'ingest:write']);
INSERT INTO commands (id, tenant_id, agent_id, type, payload, status) VALUES
    ('11111111-0000-0000-0000-000000000009', '11111111-0000-0000-0000-000000000001',
     '11111111-0000-0000-0000-000000000007', 'scan', '{"scanner":"nuclei","agent_preference":"tenant"}', 'pending');
INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, agent_preference) VALUES
    ('11111111-0000-0000-0000-00000000000a', '11111111-0000-0000-0000-000000000001', 'weekly', 'single', 'nuclei', 'tenant');

-- Module toggle, notification references, stored settings.
INSERT INTO tenant_modules (tenant_id, module_id, is_enabled) VALUES
    ('11111111-0000-0000-0000-000000000001', 'agents', true);
INSERT INTO webhooks (id, tenant_id, name, url, event_types) VALUES
    ('11111111-0000-0000-0000-00000000000b', '11111111-0000-0000-0000-000000000001', 'siem',
     'https://siem.example/hook', ARRAY['agent.offline', 'finding.created']);
INSERT INTO integrations (id, tenant_id, name, category, provider, config) VALUES
    ('11111111-0000-0000-0000-00000000000c', '11111111-0000-0000-0000-000000000001', 'slack', 'notification', 'slack', '{}'),
    ('11111111-0000-0000-0000-00000000000d', '11111111-0000-0000-0000-000000000001', 'tenable', 'security', 'tenable',
     '{"execution_mode":"agent","agent_id":"11111111-0000-0000-0000-000000000007","engine":"nessus_pro"}');
INSERT INTO integration_notification_extensions (integration_id, enabled_event_types) VALUES
    ('11111111-0000-0000-0000-00000000000c', '["agent.error", "finding.created"]');
INSERT INTO notification_preferences (tenant_id, user_id, muted_types) VALUES
    ('11111111-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000002', '["agent.offline"]');
INSERT INTO scan_workflows (id, tenant_id, name, settings) VALUES
    ('11111111-0000-0000-0000-00000000000e', '11111111-0000-0000-0000-000000000001', 'pipe',
     '{"agent_preference":"platform","max_parallel_steps":2}');

-- Provenance written by the server, and one historical audit row.
INSERT INTO assets (id, tenant_id, name, asset_type, source_type, discovery_source) VALUES
    ('11111111-0000-0000-0000-00000000000f', '11111111-0000-0000-0000-000000000001', 'host-a', 'host', 'agent', 'agent');
INSERT INTO asset_state_history (tenant_id, asset_id, change_type, source) VALUES
    ('11111111-0000-0000-0000-000000000001', '11111111-0000-0000-0000-00000000000f', 'appeared', 'agent');
INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, message) VALUES
    ('11111111-0000-0000-0000-000000000001', 'agent.created', 'agent', '11111111-0000-0000-0000-000000000007',
     'Agent ''scanner-01'' created (type: worker)');
