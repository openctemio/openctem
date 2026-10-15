-- Requests to join an organization by a verified email domain (RFC-104).
-- A verified holder of an address on a domain whose owner set join_policy
-- 'approval' asks to join; the organization's administrators decide. Rows are
-- tenant-scoped: listed and decided only by that organization, and the
-- requester sees only their own. Decided and expired rows are purged 30 days
-- after (the requester's address is personal data).
CREATE TABLE organization_join_requests (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain_id uuid REFERENCES verified_domains(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'pending',
    requested_role text NOT NULL DEFAULT 'viewer',
    decided_role text,
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_join_requests_status CHECK (status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT chk_join_requests_role CHECK (requested_role IN ('viewer', 'member')
        AND (decided_role IS NULL OR decided_role IN ('viewer', 'member')))
);

-- One pending request per person and organization.
CREATE UNIQUE INDEX uq_join_requests_pending ON organization_join_requests (tenant_id, user_id)
    WHERE status = 'pending';
CREATE INDEX idx_join_requests_tenant_status ON organization_join_requests (tenant_id, status, created_at DESC);
CREATE INDEX idx_join_requests_user ON organization_join_requests (user_id, created_at DESC);
