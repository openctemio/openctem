-- Archive of audit hash-chain rebaselines.
--
-- POST /api/v1/audit-logs/rebaseline re-signs a tenant's audit_log_chain from
-- the current audit_logs rows, overwriting prev_hash/hash. Before this table it
-- left only a WARN log line and the old hashes were gone, so an admin could
-- tamper with audit_logs, rebaseline, and leave no evidence. Now every
-- rebaseline writes one header row here, and every entry it rewrote keeps its
-- old and new hashes, in the same transaction as the rewrite.
--
-- Like audit_log_chain, these tables have no foreign key to tenants or users:
-- they are evidence and must outlive the organization and the person who ran
-- the rebaseline (actor_id is kept as a plain UUID for the same reason).

CREATE TABLE IF NOT EXISTS audit_chain_rebaselines (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    actor_id            UUID,
    entries_total       INTEGER NOT NULL CHECK (entries_total >= 0),
    entries_rewritten   INTEGER NOT NULL CHECK (entries_rewritten >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_audit_chain_rebaselines_counts CHECK (entries_rewritten <= entries_total)
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_rebaselines_tenant_created
    ON audit_chain_rebaselines(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_chain_rebaseline_entries (
    rebaseline_id   UUID NOT NULL REFERENCES audit_chain_rebaselines(id) ON DELETE RESTRICT,
    tenant_id       UUID NOT NULL,
    audit_log_id    UUID NOT NULL REFERENCES audit_logs(id) ON DELETE RESTRICT,
    chain_position  BIGINT NOT NULL,
    old_prev_hash   VARCHAR(64) NOT NULL,
    old_hash        VARCHAR(64) NOT NULL,
    new_prev_hash   VARCHAR(64) NOT NULL,
    new_hash        VARCHAR(64) NOT NULL,

    PRIMARY KEY (rebaseline_id, audit_log_id),
    -- The old values are whatever audit_log_chain held, which its own CHECKs
    -- constrain; the new ones are computed. Both must look like chain hashes.
    CONSTRAINT chk_audit_chain_rb_old_hash CHECK (old_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_audit_chain_rb_old_prev CHECK (old_prev_hash = '' OR old_prev_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_audit_chain_rb_new_hash CHECK (new_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_audit_chain_rb_new_prev CHECK (new_prev_hash = '' OR new_prev_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_rebaseline_entries_tenant_log
    ON audit_chain_rebaseline_entries(tenant_id, audit_log_id);

COMMENT ON TABLE audit_chain_rebaselines IS
    'One row per admin rebaseline of a tenant audit_log_chain. Append-only evidence.';
COMMENT ON TABLE audit_chain_rebaseline_entries IS
    'Old and new prev_hash/hash of every audit_log_chain row a rebaseline rewrote. Append-only evidence.';
