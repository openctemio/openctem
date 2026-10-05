-- EASM rejection tombstones (RFC-036 §6.4, owner decision O7: 12 months).
--
-- When a person marks a name as not the tenant's, the name and the rules that
-- supported it at that moment are kept here. Discovery does not propose the
-- name again, even after its asset is deleted, unless a rule that was not
-- there at rejection supports it. The row is removed when the decision is
-- changed to anything else, and expires after 12 months.
CREATE TABLE IF NOT EXISTS easm_tombstones (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    rules       TEXT[]      NOT NULL DEFAULT '{}',
    rejected_by UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '12 months',
    PRIMARY KEY (tenant_id, name),
    CONSTRAINT chk_easm_tombstones_name CHECK (length(name) BETWEEN 1 AND 253)
);

CREATE INDEX IF NOT EXISTS idx_easm_tombstones_expires ON easm_tombstones (expires_at);
