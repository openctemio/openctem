-- Scan approval requests (docs/rfcs/RFC-073-scan-approval-governance.md §8).
--
-- 1. scans:approve: who approves scans (owners and administrators by default;
--    any role may be given it).
-- 2. scan_approval_requests: an approval request on a scan definition. The
--    definition digest is what an approval covers: runs of an approved
--    definition need no approval, a changed definition needs a new one.
--    New table only: nothing existing changes.

INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('scans:approve', 'scans', 'Approve Scans', 'Approve or reject scan approval requests and start emergency runs (RFC-073)', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
VALUES ('00000000-0000-0000-0000-000000000001', 'scans:approve'),
       ('00000000-0000-0000-0000-000000000002', 'scans:approve')
ON CONFLICT (role_id, permission_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS scan_approval_requests (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status            VARCHAR(16) NOT NULL,
    definition_digest VARCHAR(80) NOT NULL,
    definition        JSONB NOT NULL,
    changes           JSONB NOT NULL DEFAULT '[]',
    evaluation        JSONB NOT NULL,
    justification     TEXT NOT NULL DEFAULT '',
    ticket            VARCHAR(100) NOT NULL DEFAULT '',
    run_on_approval   BOOLEAN NOT NULL DEFAULT FALSE,
    requested_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at      TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    approvals         JSONB NOT NULL DEFAULT '[]',
    valid_until       TIMESTAMPTZ,
    consumed_at       TIMESTAMPTZ,
    decided_at        TIMESTAMPTZ,
    decided_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    decision_note     TEXT NOT NULL DEFAULT '',
    reminded_at       TIMESTAMPTZ,
    emergency         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_scan_approval_status
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'superseded', 'canceled'))
);

-- At most one pending request per scan.
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_approval_pending
    ON scan_approval_requests (scan_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_scan_approval_tenant_status
    ON scan_approval_requests (tenant_id, status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_approval_scan
    ON scan_approval_requests (tenant_id, scan_id, created_at DESC);

COMMENT ON TABLE scan_approval_requests IS
    'Approval requests on scan definitions (RFC-073): what runs, how hard, against what, when and where.';
