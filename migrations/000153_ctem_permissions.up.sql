-- Migration 000153: Register CTEM permissions (RFC-004 + RFC-005)
--
-- New permissions for CTEM features: cycles, attacker profiles, business
-- services, compensating controls, priority rules, verification checklists.

INSERT INTO permissions (id, name, description) VALUES
  ('ctem:cycles:read', 'Read CTEM Cycles', 'View CTEM assessment cycles'),
  ('ctem:cycles:write', 'Write CTEM Cycles', 'Create, update, activate, and close CTEM cycles'),
  ('ctem:attacker_profiles:read', 'Read Attacker Profiles', 'View threat model attacker profiles'),
  ('ctem:attacker_profiles:write', 'Write Attacker Profiles', 'Create and update attacker profiles'),
  ('ctem:business_services:read', 'Read Business Services', 'View business service mappings'),
  ('ctem:business_services:write', 'Write Business Services', 'Create and update business services'),
  ('ctem:compensating_controls:read', 'Read Compensating Controls', 'View compensating security controls'),
  ('ctem:compensating_controls:write', 'Write Compensating Controls', 'Create, update, and test compensating controls'),
  ('ctem:priority_rules:read', 'Read Priority Rules', 'View priority override rules'),
  ('ctem:priority_rules:write', 'Write Priority Rules', 'Create and update priority override rules'),
  ('ctem:verification_checklists:read', 'Read Verification Checklists', 'View finding verification checklists'),
  ('ctem:verification_checklists:write', 'Write Verification Checklists', 'Update finding verification checklists')
ON CONFLICT (id) DO NOTHING;

-- Map to system roles
-- Owner (all 12 new permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, p.id
FROM permissions p
WHERE p.id LIKE 'ctem:%'
ON CONFLICT DO NOTHING;

-- Admin (all 12 new permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002'::uuid, p.id
FROM permissions p
WHERE p.id LIKE 'ctem:%'
ON CONFLICT DO NOTHING;

-- Member (read/write for cycles, controls, business services, verification; read for profiles; no priority rules)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, p.id
FROM permissions p
WHERE p.id IN (
  'ctem:cycles:read', 'ctem:cycles:write',
  'ctem:attacker_profiles:read',
  'ctem:business_services:read', 'ctem:business_services:write',
  'ctem:compensating_controls:read', 'ctem:compensating_controls:write',
  'ctem:verification_checklists:read', 'ctem:verification_checklists:write'
)
ON CONFLICT DO NOTHING;

-- Viewer (read-only)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000004'::uuid, p.id
FROM permissions p
WHERE p.id IN (
  'ctem:cycles:read',
  'ctem:attacker_profiles:read',
  'ctem:business_services:read',
  'ctem:compensating_controls:read',
  'ctem:verification_checklists:read'
)
ON CONFLICT DO NOTHING;
