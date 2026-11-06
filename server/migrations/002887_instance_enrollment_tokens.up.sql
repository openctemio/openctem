-- Instance enrollment tokens (docs/rfcs/RFC-100-shared-sensors.md §7): a
-- super administrator issues a single-use token, valid at most one hour, and
-- a sensor that starts pairing with it becomes a shared sensor (scope
-- instance, no tenant) without a second approval. Only the peppered hash of
-- the token is stored.

CREATE TABLE instance_enrollment_tokens (
    id uuid DEFAULT uuid_generate_v7() NOT NULL PRIMARY KEY,
    token_hash varchar(64) NOT NULL,
    name varchar(128) NOT NULL DEFAULT '',
    reason text NOT NULL,
    created_by uuid REFERENCES admin_users (id) ON DELETE SET NULL,
    created_by_email varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    used_from inet,
    CONSTRAINT ux_instance_enrollment_tokens_hash UNIQUE (token_hash),
    CONSTRAINT chk_instance_enrollment_tokens_lifetime
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 hour'),
    CONSTRAINT chk_instance_enrollment_tokens_reason CHECK (length(btrim(reason)) BETWEEN 1 AND 1000)
);

COMMENT ON TABLE instance_enrollment_tokens IS
    'Single-use tokens that enroll a shared sensor (scope instance). token_hash is HMAC-SHA256 with the sensor-key pepper; the token itself is shown once and never stored.';

-- A pairing started with such a token belongs to no tenant, ever: once the
-- sensor reveals its nonce the platform approves it as a shared sensor.
ALTER TABLE sensor_pairings ADD COLUMN instance_token_id uuid REFERENCES instance_enrollment_tokens (id);
CREATE UNIQUE INDEX ux_sensor_pairings_instance_token ON sensor_pairings (instance_token_id)
    WHERE instance_token_id IS NOT NULL;

COMMENT ON COLUMN sensor_pairings.instance_token_id IS
    'The instance enrollment token the sensor started with; such a pairing has no tenant and approves a shared sensor.';

ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_instance_no_tenant
    CHECK (instance_token_id IS NULL OR tenant_id IS NULL);

-- An approved or completed pairing is bound to a sensor and, unless it
-- enrolled a shared sensor, to a tenant.
ALTER TABLE sensor_pairings DROP CONSTRAINT chk_sensor_pairings_bound;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_bound
    CHECK (status NOT IN ('approved', 'completed')
           OR (sensor_id IS NOT NULL AND (tenant_id IS NOT NULL OR instance_token_id IS NOT NULL)));
