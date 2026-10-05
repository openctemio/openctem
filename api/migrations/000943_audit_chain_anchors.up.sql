-- Audit retention without breaking the hash chain (settings decision B4).
--
-- audit_log_chain pins every audit_logs row with ON DELETE RESTRICT, so the
-- hourly retention DELETE failed as soon as a chained row was older than the
-- retention window, and audit_logs grew without bound. Retention now prunes a
-- contiguous PREFIX of a tenant chain: the pruned rows (audit row + chain
-- entry) are first written to a JSONL archive, then one row here records the
-- chain head they leave behind, and the rows are deleted in the same
-- transaction. Verification starts from the newest anchor: the first
-- remaining entry must link to anchor_hash.
--
-- Evidence table: no foreign key to tenants, so it outlives the organization,
-- like audit_log_chain.
CREATE TABLE IF NOT EXISTS audit_chain_anchors (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL,
    -- hash of the last pruned chain entry: the prev_hash the first remaining
    -- entry must carry.
    anchor_hash          VARCHAR(64) NOT NULL,
    last_chain_position  BIGINT NOT NULL,
    pruned_count         INTEGER NOT NULL,
    oldest_logged_at     TIMESTAMPTZ NOT NULL,
    newest_logged_at     TIMESTAMPTZ NOT NULL,
    archive_path         TEXT NOT NULL,
    archive_sha256       VARCHAR(64) NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_audit_anchor_hash_hex    CHECK (anchor_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_audit_anchor_archive_hex CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_audit_anchor_count       CHECK (pruned_count > 0)
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_anchors_tenant_position
    ON audit_chain_anchors (tenant_id, last_chain_position DESC);

COMMENT ON TABLE audit_chain_anchors IS
    'Chain head left behind by each audit retention prune; verification of the remaining chain starts here. Append-only evidence.';
