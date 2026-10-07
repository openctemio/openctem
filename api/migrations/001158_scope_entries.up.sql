-- Scope entries (RFC-054 §5, owner decisions S3 and S6): a scope target
-- gains an expiry, a reason, a tier ceiling and widening approvals.
--
-- Existing rows stay as they are today: active, permanent (expires_at NULL),
-- t1, needing no approval, approved when they were created. scope_targets
-- holds a handful of rows per tenant (live: under 20 in total), so the
-- backfill UPDATE and the constraint swap take milliseconds.

ALTER TABLE scope_targets
    ADD COLUMN expires_at         timestamptz,
    ADD COLUMN reason             text        NOT NULL DEFAULT '',
    ADD COLUMN max_tier           smallint    NOT NULL DEFAULT 1,
    ADD COLUMN approvals_required smallint    NOT NULL DEFAULT 0,
    ADD COLUMN approved_at        timestamptz,
    ADD COLUMN rejected_by        varchar(200),
    ADD COLUMN rejected_at        timestamptz,
    ADD CONSTRAINT chk_scope_target_max_tier CHECK (max_tier BETWEEN 0 AND 2),
    ADD CONSTRAINT chk_scope_target_approvals CHECK (approvals_required BETWEEN 0 AND 2),
    ADD CONSTRAINT chk_scope_target_reason CHECK (length(reason) <= 1000);

UPDATE scope_targets SET approved_at = COALESCE(created_at, now()) WHERE approved_at IS NULL;

-- pending (awaiting approval), rejected and expired join active/inactive.
-- expand-contract-ok: the constraint only widens; the old api never writes the new values
ALTER TABLE scope_targets DROP CONSTRAINT chk_scope_target_status;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_target_status
    CHECK (status IN ('active', 'inactive', 'pending', 'rejected', 'expired'));

-- The active-target read filters on the expiry too.
DROP INDEX IF EXISTS idx_scope_targets_active;
CREATE INDEX idx_scope_targets_active ON scope_targets (tenant_id, status, expires_at) WHERE status = 'active';

-- Composite key for the tenant-scoped approval rows.
ALTER TABLE scope_targets ADD CONSTRAINT uq_scope_targets_tenant_id UNIQUE (tenant_id, id);

-- One row per approver of a pending entry. The (tenant_id, target_id)
-- foreign key keeps an approval inside its target's tenant.
CREATE TABLE scope_target_approvals (
    tenant_id   uuid         NOT NULL,
    target_id   uuid         NOT NULL,
    approver_id varchar(200) NOT NULL,
    approved_at timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (target_id, approver_id),
    CONSTRAINT fk_scope_target_approvals_target FOREIGN KEY (tenant_id, target_id)
        REFERENCES scope_targets (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_scope_target_approvals_tenant ON scope_target_approvals (tenant_id, target_id);

CREATE POLICY scope_target_approvals_tenant_isolation ON scope_target_approvals USING (
    tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid
    OR current_setting('app.is_platform_admin', true) = 'true');

COMMENT ON TABLE scope_target_approvals IS 'Approvals of pending scope entries (RFC-054): one row per approver; the requester never approves';
COMMENT ON COLUMN scope_targets.expires_at IS 'One-off entry expiry (RFC-054); NULL = permanent. Past it the entry authorizes nothing';
COMMENT ON COLUMN scope_targets.max_tier IS 'Tier ceiling: 0 passive, 1 safe active, 2 intrusive';
COMMENT ON COLUMN scope_targets.approvals_required IS 'Distinct approvers (not the requester) the entry needs before it is in effect';

-- Approving scope entries is its own permission: owners and admins by default.
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('attack_surface:scope:approve', 'scope', 'Approve Scope Changes', 'Create effective scope entries and approve or reject scope requests and widenings (RFC-054)', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
VALUES ('00000000-0000-0000-0000-000000000001', 'attack_surface:scope:approve'),
       ('00000000-0000-0000-0000-000000000002', 'attack_surface:scope:approve')
ON CONFLICT (role_id, permission_id) DO NOTHING;
