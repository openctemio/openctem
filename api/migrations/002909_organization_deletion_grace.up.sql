-- Organization deletion with a grace period
-- (docs/architecture/organization-deletion.md).
--
-- An owner's deletion request no longer deletes at once: the organization
-- moves to status 'pending_deletion' (refused to every credential, like a
-- suspended one) until deletion_due_at, when the purge worker deletes it. An
-- owner can cancel until then. Who asked and when is kept on the row.
--
-- tenants is small; the new status value only widens the check.
ALTER TABLE tenants
    DROP CONSTRAINT chk_tenants_status,
    ADD CONSTRAINT chk_tenants_status CHECK (status IN ('active', 'suspended', 'pending_deletion')),
    ADD COLUMN deletion_requested_at timestamptz,
    ADD COLUMN deletion_requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN deletion_due_at timestamptz,
    ADD CONSTRAINT chk_tenants_deletion_due CHECK ((status = 'pending_deletion') = (deletion_due_at IS NOT NULL));

-- The purge worker's question: which organizations are due.
CREATE INDEX idx_tenants_deletion_due ON tenants (deletion_due_at) WHERE status = 'pending_deletion';
