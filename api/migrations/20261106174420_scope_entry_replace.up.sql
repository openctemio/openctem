-- Replace a scope entry's pattern (docs/architecture/scope-entry-replace.md).
--
-- The pattern of an entry never changes: approvals, audit history and scan
-- references are bound to it. A replacement is a new entry of the same type
-- that names the entry it replaces (supersedes_id). Once it is in effect the
-- old entry is retired in the same transaction: status 'superseded', with
-- superseded_by_id naming its replacement. Until then the old entry stays in
-- effect.
--
-- Live impact: two nullable columns (no rewrite), the status constraint only
-- widens, and a partial unique index over the handful of scope rows a tenant
-- has (milliseconds).

ALTER TABLE scope_targets
    ADD COLUMN IF NOT EXISTS supersedes_id    uuid,
    ADD COLUMN IF NOT EXISTS superseded_by_id uuid;

-- The (tenant_id, id) keys keep both links inside one tenant. Deleting either
-- entry later only clears the link.
ALTER TABLE scope_targets
    ADD CONSTRAINT fk_scope_targets_supersedes FOREIGN KEY (tenant_id, supersedes_id)
        REFERENCES scope_targets (tenant_id, id) ON DELETE SET NULL (supersedes_id),
    ADD CONSTRAINT fk_scope_targets_superseded_by FOREIGN KEY (tenant_id, superseded_by_id)
        REFERENCES scope_targets (tenant_id, id) ON DELETE SET NULL (superseded_by_id);

-- expand-contract-ok: the constraint only widens; the old api never writes the new value
ALTER TABLE scope_targets DROP CONSTRAINT chk_scope_target_status;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_target_status
    CHECK (status IN ('active', 'inactive', 'pending', 'rejected', 'expired', 'superseded'));

-- At most one replacement of an entry waits for approval at a time.
CREATE UNIQUE INDEX IF NOT EXISTS ux_scope_targets_pending_replacement
    ON scope_targets (tenant_id, supersedes_id)
    WHERE supersedes_id IS NOT NULL AND status = 'pending';

COMMENT ON COLUMN scope_targets.supersedes_id IS 'The entry this one replaces (a pattern replacement); it is retired when this one takes effect';
COMMENT ON COLUMN scope_targets.superseded_by_id IS 'The entry that replaced this one; set when status becomes superseded';
