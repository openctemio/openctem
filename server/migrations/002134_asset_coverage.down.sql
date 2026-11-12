-- Restores the two narrower ledgers from asset_coverage and drops it.
-- Coverage rows of other capabilities are not kept (they had no table).

CREATE TABLE IF NOT EXISTS easm_dns_check_state (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    asset_id        uuid        NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    check_kind      text        NOT NULL,
    last_checked_at timestamptz NOT NULL,
    last_outcome    text        NOT NULL DEFAULT '',
    last_error      text        NOT NULL DEFAULT '',
    CONSTRAINT easm_dns_check_state_pkey PRIMARY KEY (asset_id, check_kind),
    CONSTRAINT fk_easm_dns_check_state_tenant_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_easm_dns_check_kind CHECK (check_kind IN ('dangling', 'email'))
);
CREATE INDEX IF NOT EXISTS idx_easm_dns_check_state_tenant
    ON easm_dns_check_state (tenant_id, check_kind, last_checked_at);

CREATE TABLE IF NOT EXISTS scan_coverage_state (
    asset_id           uuid        NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    tenant_id          uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    last_dispatched_at timestamptz NOT NULL,
    last_session_id    text,
    last_command_id    uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scan_coverage_state_pkey PRIMARY KEY (asset_id),
    CONSTRAINT fk_scan_coverage_state_tenant_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_coverage_rotation
    ON scan_coverage_state (tenant_id, last_dispatched_at);

INSERT INTO easm_dns_check_state (tenant_id, asset_id, check_kind, last_checked_at, last_outcome, last_error)
SELECT tenant_id, asset_id, substr(capability, 5), last_attempt_at, last_outcome, last_error
FROM asset_coverage
WHERE capability IN ('dns.dangling', 'dns.email') AND vantage = '' AND last_attempt_at IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at, created_at, updated_at)
SELECT asset_id, tenant_id, last_attempt_at, created_at, updated_at
FROM asset_coverage
WHERE capability = 'network_va.connector' AND vantage = '' AND last_attempt_at IS NOT NULL
ON CONFLICT DO NOTHING;

DROP TABLE IF EXISTS asset_coverage;
