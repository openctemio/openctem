-- Ownership transfer (docs/rfcs/RFC-095-role-templates-and-invitations.md):
-- the organization's owner asks an existing member to take ownership; the
-- member accepts with their own re-authentication within 72 hours, or the
-- request lapses. Accepting makes the member the owner and the previous owner
-- the role they chose (administrator by default) in one transaction.
--
-- At most one pending request per organization. Rows are deleted with their
-- organization or with either person's account; the audit log keeps the history.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS tenant_ownership_transfers (
    id                   uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id            uuid         NOT NULL,
    from_user_id         uuid         NOT NULL,
    to_user_id           uuid         NOT NULL,
    previous_owner_role  varchar(20)  NOT NULL DEFAULT 'admin',
    make_internal        boolean      NOT NULL DEFAULT false,
    status               varchar(20)  NOT NULL DEFAULT 'pending',
    created_at           timestamptz  NOT NULL DEFAULT now(),
    expires_at           timestamptz  NOT NULL,
    decided_at           timestamptz,
    decided_by           uuid,
    CONSTRAINT pk_tenant_ownership_transfers PRIMARY KEY (id),
    CONSTRAINT fk_tenant_ownership_transfers_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_ownership_transfers_from FOREIGN KEY (from_user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_ownership_transfers_to FOREIGN KEY (to_user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_ownership_transfers_decided_by FOREIGN KEY (decided_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_tenant_ownership_transfers_people CHECK (from_user_id <> to_user_id),
    CONSTRAINT chk_tenant_ownership_transfers_previous_role
        CHECK (previous_owner_role IN ('admin', 'member', 'viewer')),
    CONSTRAINT chk_tenant_ownership_transfers_status
        CHECK (status IN ('pending', 'accepted', 'canceled', 'declined', 'expired')),
    CONSTRAINT chk_tenant_ownership_transfers_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE tenant_ownership_transfers IS
    'Requests from an organization''s owner to hand ownership to an existing member; at most one pending per organization.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_ownership_transfers_pending
    ON tenant_ownership_transfers (tenant_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_tenant_ownership_transfers_tenant
    ON tenant_ownership_transfers (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenant_ownership_transfers_from
    ON tenant_ownership_transfers (from_user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_ownership_transfers_to
    ON tenant_ownership_transfers (to_user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_ownership_transfers_decided_by
    ON tenant_ownership_transfers (decided_by) WHERE decided_by IS NOT NULL;

-- Policy in shadow mode, like the other tenant tables (row security stays off).
DROP POLICY IF EXISTS tenant_ownership_transfers_tenant_isolation ON tenant_ownership_transfers;
CREATE POLICY tenant_ownership_transfers_tenant_isolation ON tenant_ownership_transfers
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
