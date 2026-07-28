-- Reconcile the finding-source catalog with the Go enum.
--
-- There are three definitions of "what is a valid finding source" and they had
-- drifted apart:
--
--   1. pkg/domain/vulnerability/value_objects.go — 18 primary + 2 legacy consts,
--      enforced by IsValid() and the `finding_source` validator tag.
--   2. the CHECK constraint on findings.source (migration 000012) — those 20
--      plus 'api'.
--   3. this catalog (migration 000038) — only 10 rows.
--
-- Consequences, both live:
--
--   * 'import' is seeded here and offered in the Add Finding dialog, but it is
--     not a Go const and NOT in the CHECK — so choosing it fails the insert.
--     Verified against the live database: source='import' violates the check
--     constraint while 'sast' and 'api' insert fine.
--   * easm and cspm are legal Go values that findings actually carry, but have
--     no catalog row, so the UI cannot label or group them.
--
-- The Go enum is the source of truth: it is what the constructor validates
-- against. This migration makes the catalog match it.
--
-- The CHECK is deliberately left alone. It is a superset (Go ⊆ CHECK already
-- holds), and narrowing it to drop 'api' would be a destructive change for any
-- deployment that has such rows — this one has none, but that is not a
-- guarantee about others. A more permissive database than application is safe;
-- the reverse is what broke 'import'.

-- Two categories the original seed predates: attack-surface and cloud work did
-- not exist in April, which is why easm/cspm had nowhere to live.
INSERT INTO finding_source_categories (code, name, description, icon, color, display_order) VALUES
('attack_surface', 'Attack Surface', 'External attack surface discovery and exposure', 'radar', 'sky', 7),
('cloud', 'Cloud', 'Cloud configuration and posture', 'cloud', 'teal', 8)
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    updated_at = NOW();

-- 'external' is what the Go enum calls the thing this catalog called
-- 'import'. Same meaning, and only one of the two can actually be stored.
INSERT INTO finding_sources (code, name, description, icon, color, display_order, category_id) VALUES
('easm', 'EASM', 'External Attack Surface Management - exposed assets and services', 'radar', 'sky', 11,
    (SELECT id FROM finding_source_categories WHERE code = 'attack_surface')),
('cspm', 'CSPM', 'Cloud Security Posture Management - cloud misconfiguration', 'cloud', 'teal', 12,
    (SELECT id FROM finding_source_categories WHERE code = 'cloud')),
('external', 'External Import', 'Imported from an external tool or platform', 'upload', 'slate', 13,
    (SELECT id FROM finding_source_categories WHERE code = 'import')),
('threat_intel', 'Threat Intel', 'Threat intelligence feeds', 'crosshair', 'rose', 14,
    (SELECT id FROM finding_source_categories WHERE code = 'import')),
('vendor', 'Vendor Assessment', 'Third-party or vendor security assessment', 'building', 'stone', 15,
    (SELECT id FROM finding_source_categories WHERE code = 'import')),
('rasp', 'RASP', 'Runtime Application Self-Protection', 'shield-check', 'emerald', 16,
    (SELECT id FROM finding_source_categories WHERE code = 'runtime')),
('waf', 'WAF', 'Web Application Firewall', 'shield-alert', 'lime', 17,
    (SELECT id FROM finding_source_categories WHERE code = 'runtime')),
('siem', 'SIEM', 'Security Information and Event Management', 'activity', 'green', 18,
    (SELECT id FROM finding_source_categories WHERE code = 'runtime')),
('bug_bounty', 'Bug Bounty', 'Reported through a bug bounty program', 'award', 'violet', 19,
    (SELECT id FROM finding_source_categories WHERE code = 'manual')),
('red_team', 'Red Team', 'Red team exercise', 'swords', 'fuchsia', 20,
    (SELECT id FROM finding_source_categories WHERE code = 'manual')),
('sca_tool', 'SCA (legacy)', 'Legacy alias for SCA; retained so existing rows remain displayable', 'package', 'purple', 90,
    (SELECT id FROM finding_source_categories WHERE code = 'dependency'))
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    category_id = EXCLUDED.category_id,
    updated_at = NOW();

-- Retire the unstorable row. No finding can reference it — the CHECK has always
-- rejected it — so there is nothing to migrate, only a dropdown option to stop
-- offering. Deactivated rather than deleted so any UI holding the id degrades
-- to a hidden entry instead of a dangling reference.
UPDATE finding_sources
SET is_active = FALSE,
    description = 'Retired: superseded by ''external''. This code was never accepted by the findings.source CHECK constraint.',
    updated_at = NOW()
WHERE code = 'import';
