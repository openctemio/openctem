-- 000096: Add Attack Simulation and Control Testing modules (validation category)
-- These are separate from Pentest — different workflows, users, and data models.
-- Disabled by default (is_active = false, beta). Admin enables via Settings > Modules.

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, release_status, is_core)
VALUES
  ('attack_simulation', 'attack-simulation', 'Attack Simulation',
   'Breach & Attack Simulation (BAS) — automated adversary emulation to test security controls effectiveness',
   'Swords', 'validation', 31, true, 'beta', false),
  ('control_testing', 'control-testing', 'Control Testing',
   'Validate security controls (firewalls, WAF, IDS/IPS) with automated test cases',
   'ShieldCheck', 'validation', 32, true, 'beta', false)
ON CONFLICT (id) DO NOTHING;

-- Pre-register for tenants that have pentest enabled (disabled by default)
INSERT INTO tenant_modules (tenant_id, module_id, is_enabled)
SELECT tm.tenant_id, m.id, false
FROM tenant_modules tm
CROSS JOIN (SELECT id FROM modules WHERE id IN ('attack_simulation', 'control_testing')) m
WHERE tm.module_id = 'pentest' AND tm.is_enabled = true
ON CONFLICT DO NOTHING;
