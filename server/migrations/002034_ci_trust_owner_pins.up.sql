-- The immutable id of each CI organization or namespace a trust
-- configuration admitted, pinned at its first admitted exchange (RFC-077
-- G-10): a name that later belongs to another organization is refused.
CREATE TABLE IF NOT EXISTS ci_trust_owner_pins (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    trust_config_id UUID NOT NULL,
    owner_name      VARCHAR(500) NOT NULL,
    owner_id        VARCHAR(64) NOT NULL,
    pinned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (trust_config_id, owner_name),
    CONSTRAINT fk_ci_trust_owner_pins_config FOREIGN KEY (tenant_id, trust_config_id)
        REFERENCES ci_trust_configs (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ci_trust_owner_pins_tenant ON ci_trust_owner_pins (tenant_id);
