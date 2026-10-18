-- Organization suspension and platform-wide account block
-- (docs/architecture/organization-suspension.md).
--
-- tenants.status: 'active' or 'suspended'. A suspended organization is
-- refused to every credential (sessions, API keys, MCP tokens, sensor keys,
-- SCIM tokens, CI run tokens, inbound webhooks) and its scheduled work is
-- skipped; nothing is deleted. Who suspended it and why is kept on the row
-- (the reason is shown to platform administrators only).
--
-- users.blocked_*: who blocked an account platform-wide and why. The block
-- itself is users.status = 'suspended' (the value the sign-in and per-request
-- checks already refuse).
--
-- Both tables are small; adding columns with a constant default and a check
-- every existing row passes is brief.
ALTER TABLE tenants
    ADD COLUMN status varchar(20) NOT NULL DEFAULT 'active',
    ADD COLUMN suspended_at timestamptz,
    ADD COLUMN suspended_by uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    ADD COLUMN suspended_reason text,
    ADD CONSTRAINT chk_tenants_status CHECK (status IN ('active', 'suspended'));

-- The background jobs and the access gate ask "is this organization active";
-- the few that are not are found through this partial index.
CREATE INDEX idx_tenants_not_active ON tenants (id) WHERE status <> 'active';

ALTER TABLE users
    ADD COLUMN blocked_at timestamptz,
    ADD COLUMN blocked_by uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    ADD COLUMN blocked_reason text;
