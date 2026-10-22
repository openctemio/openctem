-- Durable Idempotency-Key store (docs/rfcs/RFC-122-ingest-receipts.md §6).
--
-- One row per (tenant, principal, route, key hash): the request fingerprint,
-- the state (pending while the first request runs, done once it succeeded)
-- and the stored answer that a retry with the same key and fingerprint gets
-- back. The key itself is never stored, only its SHA-256. Rows expire (a
-- pending one after the request deadline, a done one after 24 hours) and an
-- hourly job deletes them.
--
-- Live impact: a new empty table.

CREATE TABLE IF NOT EXISTS idempotency_keys (
    tenant_id      uuid        NOT NULL,
    principal      varchar(80) NOT NULL,
    route          varchar(64) NOT NULL,
    key_hash       char(64)    NOT NULL,
    request_sha256 char(64),
    state          varchar(8)  NOT NULL,
    -- The request that holds a pending key: only it may finish or release
    -- the key, so a request whose key expired and was taken over cannot
    -- overwrite the next one's record.
    claim_token    uuid        NOT NULL,
    status         integer,
    response       bytea,
    receipt_id     uuid,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    CONSTRAINT pk_idempotency_keys PRIMARY KEY (tenant_id, principal, route, key_hash),
    CONSTRAINT fk_idempotency_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_idempotency_keys_state CHECK (state IN ('pending', 'done')),
    CONSTRAINT chk_idempotency_keys_hash CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_idempotency_keys_done CHECK (state <> 'done' OR (request_sha256 IS NOT NULL AND status IS NOT NULL AND response IS NOT NULL))
);
COMMENT ON TABLE idempotency_keys IS
    'Idempotency-Key records: per tenant, principal (user:<id> or key:<id>) and route, the SHA-256 of the key, the request fingerprint and, once done, the stored answer replayed to a retry. Expired rows are deleted hourly.';

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires ON idempotency_keys (expires_at);

DROP POLICY IF EXISTS idempotency_keys_tenant_isolation ON idempotency_keys;
CREATE POLICY idempotency_keys_tenant_isolation ON idempotency_keys
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
