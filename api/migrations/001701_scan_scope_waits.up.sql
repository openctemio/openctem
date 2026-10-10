-- A scan saved to start when its scope is approved (RFC-054 §7): its direct
-- targets were refused only because the scope entries that cover them wait
-- for approval. When an entry of the tenant comes into effect, the waiting
-- scans whose targets now pass the gate are started once, as the person who
-- asked, and every gate runs again at that start. A row expires unused.

CREATE TABLE scan_scope_waits (
    scan_id      UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_scan_scope_waits_tenant ON scan_scope_waits (tenant_id, expires_at);
COMMENT ON TABLE scan_scope_waits IS
    'Scans that start once when the pending scope entries covering their targets are approved (RFC-054 §7).';
