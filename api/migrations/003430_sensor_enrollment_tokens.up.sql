-- Organization enrollment tokens (docs/architecture/sensor-pairing.md,
-- "Enrollment tokens"): an organization administrator issues a token for
-- unattended installs (Kubernetes, Terraform, many hosts). A sensor that
-- starts pairing with it runs the same key-bound exchange as every pairing
-- (its own Ed25519 key, the platform's signed answer, the nonce commitment,
-- a signed confirmation); the token carries the administrator's approval and
-- presets (zones, grant profile, sensor type, labels), so no fingerprint
-- compare is asked unless require_approval is set. Every enrolled sensor
-- starts at trust level New. Only the keyed hash of the token is stored.

CREATE TABLE sensor_enrollment_tokens (
    id uuid DEFAULT uuid_generate_v7() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name varchar(128) NOT NULL,
    token_hash varchar(64) NOT NULL,
    token_hint varchar(8) NOT NULL,
    max_uses integer NOT NULL,
    use_count integer NOT NULL DEFAULT 0,
    require_approval boolean NOT NULL DEFAULT false,
    sensor_type varchar(32) NOT NULL DEFAULT 'worker',
    grant_profile varchar(128) NOT NULL DEFAULT '',
    zone_ids uuid[] NOT NULL DEFAULT '{}',
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    allowed_cidrs cidr[] NOT NULL DEFAULT '{}',
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    last_used_from inet,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT ux_sensor_enrollment_tokens_hash UNIQUE (token_hash),
    CONSTRAINT chk_sensor_enrollment_tokens_uses
        CHECK (max_uses BETWEEN 1 AND 1000 AND use_count BETWEEN 0 AND max_uses),
    CONSTRAINT chk_sensor_enrollment_tokens_lifetime
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
    CONSTRAINT chk_sensor_enrollment_tokens_name CHECK (length(btrim(name)) BETWEEN 1 AND 128),
    CONSTRAINT chk_sensor_enrollment_tokens_labels CHECK (jsonb_typeof(labels) = 'object')
);

CREATE INDEX ix_sensor_enrollment_tokens_tenant ON sensor_enrollment_tokens (tenant_id, created_at DESC);

COMMENT ON TABLE sensor_enrollment_tokens IS
    'Organization enrollment tokens for unattended sensor installs. token_hash is HMAC-SHA256 with the sensor-key pepper; the token is shown once and never stored. use_count counts distinct sensor keys.';

-- A pairing started with such a token belongs to the token's tenant from the
-- start; it is approved when the sensor reveals its nonce (or waits for an
-- administrator when the token requires approval).
ALTER TABLE sensor_pairings ADD COLUMN enrollment_token_id uuid
    REFERENCES sensor_enrollment_tokens (id) ON DELETE SET NULL;
CREATE INDEX ix_sensor_pairings_enrollment_token ON sensor_pairings (enrollment_token_id, thumbprint)
    WHERE enrollment_token_id IS NOT NULL;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_enrollment_tenant
    CHECK (enrollment_token_id IS NULL OR (tenant_id IS NOT NULL AND instance_token_id IS NULL));

COMMENT ON COLUMN sensor_pairings.enrollment_token_id IS
    'The organization enrollment token the sensor started with (tenant set from the token).';
