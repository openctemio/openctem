ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved;
ALTER TABLE roles ADD CONSTRAINT roles_custom_slug_not_reserved
    CHECK (is_system OR lower(btrim(slug)) !~ '^(owner|admin|member|viewer)$') NOT VALID;

DELETE FROM user_roles WHERE role_id = '00000000-0000-0000-0000-000000000005';
DELETE FROM role_permissions WHERE role_id = '00000000-0000-0000-0000-000000000005';
DELETE FROM roles WHERE id = '00000000-0000-0000-0000-000000000005';
DELETE FROM role_permissions WHERE permission_id IN ('attack_surface:programs:read', 'attack_surface:programs:write');
DELETE FROM permissions WHERE id IN ('attack_surface:programs:read', 'attack_surface:programs:write');

DROP TABLE IF EXISTS scan_run_scope_snapshots;
DROP TABLE IF EXISTS scope_snapshots;

-- Program entries leave with their programs.
DELETE FROM scope_targets WHERE authorization_source = 'program';
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin IN
    ('manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system'));
DROP INDEX IF EXISTS idx_scope_targets_program;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS fk_scope_targets_program;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_program;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_authorization_source;
ALTER TABLE scope_targets DROP COLUMN IF EXISTS program_id;
ALTER TABLE scope_targets DROP COLUMN IF EXISTS authorization_source;

DROP TABLE IF EXISTS bounty_program_exclusions;
DROP TABLE IF EXISTS bounty_programs;

ALTER TABLE groups DROP CONSTRAINT IF EXISTS uq_groups_tenant_id_id;
