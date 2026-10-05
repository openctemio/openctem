-- =============================================================================
-- Migration 001085: interactive sensor pairing (RFC-052 SP1)
-- =============================================================================
-- 1. sensor_pairings: one row per pairing request. A default-mode request is
--    created by an unauthenticated (but key-signed) sensor and has NO tenant
--    until an administrator approves it; a reverse-mode row ("expect a
--    sensor") starts with a tenant and a code but no key. Codes are stored as
--    a keyed HMAC, never in clear.
-- 2. tenants.sensor_bearer_keys_allowed: whether new bearer-key (octs_)
--    sensors may be created. Existing organizations keep the option (true);
--    new organizations require key-bound identity (default false, D-4).
-- 3. Five permissions, granted to owner and admin and admin-only:
--    sensors:pair, sensors:approve, sensors:grant:narrow, sensors:grant:widen,
--    sensors:revoke. The admin-only trigger (000945, last replaced by 001077) is extended to them.
--
-- Live-database safety: ADD COLUMN with a constant default is catalog-only;
-- the default is then changed for future rows (no rewrite). The new table is
-- empty. The trigger function is replaced in place.
-- =============================================================================

SET lock_timeout = '5s';

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS sensor_bearer_keys_allowed BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE tenants
    ALTER COLUMN sensor_bearer_keys_allowed SET DEFAULT FALSE;
COMMENT ON COLUMN tenants.sensor_bearer_keys_allowed IS
    'Whether new bearer-key (octs_) sensors may be created; false = key-bound identity (pairing) only. RFC-052 D-4.';

CREATE TABLE IF NOT EXISTS sensor_pairings (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    mode                VARCHAR(16) NOT NULL,
    status              VARCHAR(16) NOT NULL,
    tenant_id           UUID REFERENCES tenants (id) ON DELETE CASCADE,
    code_hash           VARCHAR(64),
    public_key          BYTEA,
    thumbprint          VARCHAR(43),
    commitment          BYTEA,
    sensor_nonce        BYTEA,
    platform_nonce      BYTEA,
    sas                 VARCHAR(128),
    host_facts          JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_ip           INET,
    repair_sensor_id    UUID,
    sensor_id           UUID,
    requested_name      VARCHAR(255),
    requested_zone_ids  UUID[],
    requested_profile   VARCHAR(64),
    created_by          UUID REFERENCES users (id) ON DELETE SET NULL,
    approved_by         UUID REFERENCES users (id) ON DELETE SET NULL,
    approved_at         TIMESTAMPTZ,
    denied_by           UUID REFERENCES users (id) ON DELETE SET NULL,
    denied_at           TIMESTAMPTZ,
    confirmed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    CONSTRAINT chk_sensor_pairings_mode CHECK (mode IN ('forward', 'reverse')),
    CONSTRAINT chk_sensor_pairings_status CHECK (status IN ('expecting', 'pending', 'approved', 'completed', 'denied', 'expired')),
    CONSTRAINT chk_sensor_pairings_public_key CHECK (public_key IS NULL OR octet_length(public_key) = 32),
    CONSTRAINT chk_sensor_pairings_nonces CHECK (
        (commitment IS NULL OR octet_length(commitment) = 32) AND
        (sensor_nonce IS NULL OR octet_length(sensor_nonce) = 32) AND
        (platform_nonce IS NULL OR octet_length(platform_nonce) = 32)),
    -- A key is present once the sensor has spoken; only an expectation
    -- (reverse mode, before the sensor connects) has none.
    CONSTRAINT chk_sensor_pairings_key CHECK ((status = 'expecting') = (public_key IS NULL)),
    -- Approved and completed rows belong to exactly one tenant and sensor.
    CONSTRAINT chk_sensor_pairings_bound CHECK (status NOT IN ('approved', 'completed') OR (tenant_id IS NOT NULL AND sensor_id IS NOT NULL))
);

-- An open code is unique (a collision on 40 bits is retried by the service).
CREATE UNIQUE INDEX IF NOT EXISTS ux_sensor_pairings_open_code
    ON sensor_pairings (code_hash) WHERE status IN ('expecting', 'pending') AND code_hash IS NOT NULL;
-- One key is in at most one live pairing.
CREATE UNIQUE INDEX IF NOT EXISTS ux_sensor_pairings_live_key
    ON sensor_pairings (thumbprint) WHERE status IN ('pending', 'approved');
-- The open-request cap and the expiry sweep.
CREATE INDEX IF NOT EXISTS ix_sensor_pairings_status_expiry ON sensor_pairings (status, expires_at);
CREATE INDEX IF NOT EXISTS ix_sensor_pairings_tenant ON sensor_pairings (tenant_id, created_at DESC) WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE sensor_pairings IS
    'Interactive sensor pairing requests (RFC-052). tenant_id is NULL until an administrator approves a default-mode request.';

INSERT INTO permissions (id, module_id, name, description) VALUES
    ('sensors:pair', 'sensors', 'Pair Sensors', 'Look up a pairing code, expect a sensor and deny pairing requests'),
    ('sensors:approve', 'sensors', 'Approve Sensors', 'Approve a pairing request: bind a sensor key to this organization (with re-authentication)'),
    ('sensors:grant:narrow', 'sensors', 'Narrow Sensor Grants', 'Narrow what a sensor may do (zones, tools, tier, targets, credentials, push ingest) and demote its trust level'),
    ('sensors:grant:widen', 'sensors', 'Widen Sensor Grants', 'Widen what a sensor may do and promote its trust level (audited, all administrators notified)'),
    ('sensors:revoke', 'sensors', 'Revoke Sensors', 'Revoke a sensor or one of its keys')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.id
FROM (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid), -- owner
    ('00000000-0000-0000-0000-000000000002'::uuid)  -- admin
) AS r(role_id)
CROSS JOIN permissions p
WHERE p.id IN ('sensors:pair', 'sensors:approve', 'sensors:grant:narrow', 'sensors:grant:widen', 'sensors:revoke')
ON CONFLICT DO NOTHING;

-- The admin-only backstop (000945) covers the new permissions too.
CREATE OR REPLACE FUNCTION refuse_admin_only_permission_on_custom_role()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete',
                             'scans:ci:write', 'scans:ci:override',
                             'sensors:pair', 'sensors:approve', 'sensors:grant:narrow',
                             'sensors:grant:widen', 'sensors:revoke')
       AND EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'permission % is reserved for the owner and admin roles and cannot be put on a custom role',
            NEW.permission_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
