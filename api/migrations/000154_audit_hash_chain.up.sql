-- Audit log hash-chain (tamper-evident append-only ledger).
--
-- Instead of mutating the existing audit_logs table (which is wide and
-- referenced from many code paths) this migration adds a thin side
-- table that pins each audit row into a cryptographic chain per tenant.
--
-- Each new row stores:
--   - hash: SHA-256 hex of (prev_hash || audit_log_payload || timestamp)
--   - prev_hash: hash of the previous chain entry for the same tenant
--                ("" for the first entry per tenant)
--   - chain_position: monotonic per-tenant counter (fast "Nth entry" lookup)
--
-- Verify procedure:
--   SELECT audit_log_id, prev_hash, hash, chain_position
--     FROM audit_log_chain
--    WHERE tenant_id = $1
--    ORDER BY chain_position;
--   then for each row, recompute hash and assert prev_hash matches the
--   previous row's hash.
--
-- Why a side table, not columns on audit_logs:
--   - audit_logs is wide (~20 cols) and shared with legacy analytics
--     queries; adding two more cols touches many rows at migration time.
--   - The chain is append-only per its own semantics; keeping it
--     separate lets operators run a separate WORM backup of just this
--     table for long-term integrity.
--   - A future partition-by-month scheme on audit_log_chain is natural.
--
-- Rollback (in the .down.sql) drops the table — existing audit_logs
-- rows keep their integrity via the app-level logging, just without
-- the cryptographic chain.

CREATE TABLE IF NOT EXISTS audit_log_chain (
    audit_log_id    UUID PRIMARY KEY REFERENCES audit_logs(id) ON DELETE RESTRICT,
    tenant_id       UUID NOT NULL,
    prev_hash       VARCHAR(64) NOT NULL DEFAULT '',
    hash            VARCHAR(64) NOT NULL,
    chain_position  BIGSERIAL NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_audit_chain_hash_hex   CHECK (hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_audit_chain_prev_hex   CHECK (prev_hash = '' OR prev_hash ~ '^[0-9a-f]{64}$')
);

-- Per-tenant ordering: the typical query is "walk the chain for tenant T".
CREATE INDEX IF NOT EXISTS idx_audit_log_chain_tenant_position
    ON audit_log_chain(tenant_id, chain_position);

-- Lookups when verifying a specific audit log.
CREATE INDEX IF NOT EXISTS idx_audit_log_chain_tenant_hash
    ON audit_log_chain(tenant_id, hash);

COMMENT ON TABLE audit_log_chain IS
    'Tamper-evident SHA-256 hash-chain anchoring each audit_logs row per tenant. Append-only by design.';
