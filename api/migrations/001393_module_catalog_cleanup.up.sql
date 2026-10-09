-- Module catalog cleanup.
--
-- 1. Every permission belongs to a live module. The role editor lists a
--    permission under its module (permission_repository: modules WHERE
--    is_active), so permissions whose module was NULL (ctem:*) or retired
--    (scope, secrets, sources) were missing from it: an administrator could
--    not grant scope, cycle, business-service or priority-rule permissions
--    from the console.
-- 2. Retired modules go: rows that are inactive or deprecated, and modules
--    that gate nothing (vulnerabilities, commands, remediation_tasks: the
--    remediation pages and API follow `remediation`). Their tenant overrides
--    switched nothing.
-- 3. The modules every preset forced on and the toggle API refused to switch
--    off (sensors, groups, api_keys, notification_settings, integrations,
--    integrations.notifications) are core: the settings page no longer shows
--    a switch that cannot be used.
--
-- Idempotent.

-- 1. Permissions -> live modules.
UPDATE permissions SET module_id = 'scope_config' WHERE module_id = 'scope';
UPDATE permissions SET module_id = 'scans' WHERE module_id IN ('secrets', 'sources');
UPDATE permissions SET module_id = 'findings' WHERE module_id = 'vulnerabilities';
UPDATE permissions SET module_id = 'attacker_profiles' WHERE module_id IS NULL AND id LIKE 'ctem:attacker_profiles:%';
UPDATE permissions SET module_id = 'business_services' WHERE module_id IS NULL AND id LIKE 'ctem:business_services:%';
UPDATE permissions SET module_id = 'compensating_controls' WHERE module_id IS NULL AND id LIKE 'ctem:compensating_controls:%';
UPDATE permissions SET module_id = 'ctem_cycles' WHERE module_id IS NULL AND id LIKE 'ctem:cycles:%';
UPDATE permissions SET module_id = 'priority_rules' WHERE module_id IS NULL AND id LIKE 'ctem:priority_rules:%';
UPDATE permissions SET module_id = 'findings' WHERE module_id IS NULL AND id LIKE 'ctem:verification_checklists:%';
UPDATE permissions SET module_id = 'remediation' WHERE module_id = 'remediation_tasks';

-- 2. Retired modules: move anything filed under them, drop the overrides
--    (tenant_modules has no ON DELETE), then the rows.
UPDATE event_types SET module_id = NULL
 WHERE module_id IN ('billing', 'licensing', 'platform', 'subscription', 'usage', 'policies', 'scope',
                     'secrets', 'sources', 'webhooks', 'integrations.webhooks', 'vulnerabilities', 'commands',
                     'remediation_tasks');
UPDATE asset_types SET module_id = NULL
 WHERE module_id IN ('scope', 'secrets', 'sources', 'vulnerabilities', 'commands', 'remediation_tasks');

DELETE FROM tenant_modules
 WHERE module_id IN ('billing', 'licensing', 'platform', 'subscription', 'usage', 'policies', 'scope',
                     'secrets', 'sources', 'webhooks', 'integrations.webhooks', 'vulnerabilities', 'commands',
                     'remediation_tasks');
DELETE FROM modules
 WHERE id IN ('billing', 'licensing', 'platform', 'subscription', 'usage', 'policies', 'scope',
              'secrets', 'sources', 'webhooks', 'integrations.webhooks', 'vulnerabilities', 'commands',
              'remediation_tasks');

-- 3. Always-on modules are core.
UPDATE modules SET is_core = TRUE
 WHERE id IN ('sensors', 'groups', 'api_keys', 'notification_settings', 'integrations',
              'integrations.notifications');
DELETE FROM tenant_modules
 WHERE module_id IN ('sensors', 'groups', 'api_keys', 'notification_settings', 'integrations',
                     'integrations.notifications');
