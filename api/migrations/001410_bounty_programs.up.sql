-- Bug-bounty programs, authorization sources and the Researcher role
-- (RFC-065). New tables are empty; scope_targets gets two columns with a
-- default (no rewrite: a constant default is metadata only), and the few
-- small constraint and index changes take milliseconds on live data.

-- groups: composite key so a program's group stays inside its tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_tenant_id_id ON groups (tenant_id, id);
ALTER TABLE groups ADD CONSTRAINT uq_groups_tenant_id_id UNIQUE USING INDEX uq_groups_tenant_id_id;

CREATE TABLE bounty_programs (
    id            uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id     uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name          text        NOT NULL,
    platform      text        NOT NULL DEFAULT '',
    handle        text        NOT NULL DEFAULT '',
    program_url   text        NOT NULL,
    status        text        NOT NULL DEFAULT 'active',
    scope_source  text        NOT NULL DEFAULT 'paste',
    authoritative boolean     NOT NULL DEFAULT false,
    rules         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    scope_items   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    terms_sha256  text        NOT NULL,
    accepted_by   uuid,
    accepted_at   timestamptz,
    group_id      uuid,
    created_by    uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT uq_bounty_programs_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_bounty_programs_group FOREIGN KEY (tenant_id, group_id)
        REFERENCES groups (tenant_id, id) ON DELETE SET NULL (group_id),
    CONSTRAINT chk_bounty_programs_status CHECK (status IN ('active', 'paused', 'ended')),
    CONSTRAINT chk_bounty_programs_source CHECK (scope_source IN ('paste')),
    CONSTRAINT chk_bounty_programs_name CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    CONSTRAINT chk_bounty_programs_platform CHECK (length(platform) <= 50),
    CONSTRAINT chk_bounty_programs_handle CHECK (length(handle) <= 100),
    CONSTRAINT chk_bounty_programs_url CHECK (program_url LIKE 'https://%' AND length(program_url) <= 500),
    CONSTRAINT chk_bounty_programs_terms CHECK (terms_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_bounty_programs_rules CHECK (jsonb_typeof(rules) = 'object'),
    CONSTRAINT chk_bounty_programs_items CHECK (jsonb_typeof(scope_items) = 'array')
);
CREATE UNIQUE INDEX uq_bounty_programs_tenant_name ON bounty_programs (tenant_id, lower(name));
CREATE INDEX idx_bounty_programs_group ON bounty_programs (group_id) WHERE group_id IS NOT NULL;

COMMENT ON TABLE bounty_programs IS 'Bug-bounty and disclosure programs the organization tests under their published rules (RFC-065)';
COMMENT ON COLUMN bounty_programs.terms_sha256 IS 'SHA-256 of the canonical terms (program URL, rules, in and out of scope) the last attestation accepted';
COMMENT ON COLUMN bounty_programs.group_id IS 'The group whose members work on the program (data scope)';

-- Out-of-scope items of a program: they stop program entries (any program
-- of the tenant) from covering a name; ownership entries are unaffected.
CREATE TABLE bounty_program_exclusions (
    id          uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id   uuid        NOT NULL,
    program_id  uuid        NOT NULL,
    target_type text        NOT NULL,
    pattern     text        NOT NULL,
    reason      text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT fk_bounty_program_exclusions_program FOREIGN KEY (tenant_id, program_id)
        REFERENCES bounty_programs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_bounty_program_exclusions_type CHECK (target_type IN ('domain', 'ip_address', 'ip_range', 'cidr', 'url')),
    CONSTRAINT chk_bounty_program_exclusions_pattern CHECK (length(pattern) BETWEEN 1 AND 500),
    CONSTRAINT uq_bounty_program_exclusions UNIQUE (program_id, target_type, pattern)
);
CREATE INDEX idx_bounty_program_exclusions_tenant ON bounty_program_exclusions (tenant_id);

-- Authorization source of a scope entry.
ALTER TABLE scope_targets
    ADD COLUMN IF NOT EXISTS authorization_source text NOT NULL DEFAULT 'ownership',
    ADD COLUMN IF NOT EXISTS program_id uuid;
ALTER TABLE scope_targets
    ADD CONSTRAINT chk_scope_targets_authorization_source
    CHECK (authorization_source IN ('ownership', 'program', 'authorization_letter', 'self_attestation')) NOT VALID;
ALTER TABLE scope_targets VALIDATE CONSTRAINT chk_scope_targets_authorization_source;
ALTER TABLE scope_targets
    ADD CONSTRAINT chk_scope_targets_program
    CHECK ((authorization_source = 'program') = (program_id IS NOT NULL)) NOT VALID;
ALTER TABLE scope_targets VALIDATE CONSTRAINT chk_scope_targets_program;
ALTER TABLE scope_targets
    ADD CONSTRAINT fk_scope_targets_program FOREIGN KEY (tenant_id, program_id)
    REFERENCES bounty_programs (tenant_id, id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_scope_targets_program ON scope_targets (program_id) WHERE program_id IS NOT NULL;

-- expand-contract-ok: the constraint only widens; the old api never writes 'program'
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin IN
    ('manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program'));

COMMENT ON COLUMN scope_targets.authorization_source IS 'Why the entry authorizes probes: ownership, program (RFC-065), authorization_letter, self_attestation';
COMMENT ON COLUMN scope_targets.program_id IS 'The program a program entry belongs to';

-- Scope snapshots: the scope in force when a scan run started, stored once
-- per distinct body.
CREATE TABLE scope_snapshots (
    tenant_id  uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    sha256     text        NOT NULL,
    body       jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sha256),
    CONSTRAINT chk_scope_snapshots_sha CHECK (sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE scan_run_scope_snapshots (
    tenant_id uuid        NOT NULL,
    run_id    uuid        NOT NULL,
    sha256    text        NOT NULL,
    taken_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id),
    CONSTRAINT fk_scan_run_scope_snapshots_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES scan_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_scope_snapshots_snapshot FOREIGN KEY (tenant_id, sha256)
        REFERENCES scope_snapshots (tenant_id, sha256)
);
CREATE INDEX idx_scan_run_scope_snapshots_sha ON scan_run_scope_snapshots (tenant_id, sha256);

-- Permissions: programs (owner and admin by default).
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('attack_surface:programs:read', 'scope', 'View Programs', 'View bug-bounty programs, their scope, rules and snapshots (RFC-065)', true),
    ('attack_surface:programs:write', 'scope', 'Manage Programs', 'Import, re-import, pause, resume and end bug-bounty programs and attest to their terms (RFC-065)', true)
ON CONFLICT (id) DO NOTHING;

-- The Researcher system role.
INSERT INTO roles (id, tenant_id, slug, name, description, is_system, hierarchy_level, has_full_data_access)
VALUES ('00000000-0000-0000-0000-000000000005', NULL, 'researcher', 'Researcher',
        'Tests programs the organization follows: programs, scans and findings of the programs they belong to; cannot change the organization''s own scope or approve anything',
        true, 30, false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM (VALUES ('00000000-0000-0000-0000-000000000001'::uuid), ('00000000-0000-0000-0000-000000000002'::uuid)) AS r (role_id)
CROSS JOIN (VALUES ('attack_surface:programs:read'), ('attack_surface:programs:write')) AS p (permission_id)
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000005'::uuid, p.id
FROM permissions p
WHERE p.id IN ('dashboard:read', 'assets:read',
               'findings:read', 'findings:write', 'findings:status', 'findings:triage', 'findings:export',
               'scans:read', 'scans:write', 'scans:execute',
               'scans:profiles:read', 'scans:templates:read', 'scans:workflows:read',
               'sensors:read',
               'attack_surface:programs:read', 'attack_surface:programs:write')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- A custom role may not take the new system slug.
-- expand-contract-ok: NOT VALID leaves any existing custom role alone; new rows are checked
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved;
ALTER TABLE roles ADD CONSTRAINT roles_custom_slug_not_reserved
    CHECK (is_system OR lower(btrim(slug)) !~ '^(owner|admin|member|viewer|researcher)$') NOT VALID;
