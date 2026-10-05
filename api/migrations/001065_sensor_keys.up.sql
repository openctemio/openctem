-- =============================================================================
-- Migration 001065: key-bound sensor identity (RFC-052 SP1, RFC-032 E4/E5)
-- =============================================================================
-- A paired sensor holds an Ed25519 private key and signs every request
-- (RFC 9421). The platform keeps only the public key, here. A key is pending
-- from the approval of a pairing until the sensor confirms it, then active,
-- and revoked for good on re-pair or revocation.
--
-- sensors.auth_kind says how a sensor authenticates: bearer (an octs_/rda_
-- key, every existing sensor) or key_bound. A key-bound sensor has no bearer
-- key: its api_key_hash holds an unmatchable placeholder ("!kb:" + random hex;
-- stored hashes are lower-case hex).
--
-- Live-database safety: ADD COLUMN with a constant default changes only the
-- catalog (no table rewrite); the new table is empty.
-- =============================================================================

SET lock_timeout = '5s';

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS auth_kind VARCHAR(16) NOT NULL DEFAULT 'bearer';

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_auth_kind;
ALTER TABLE sensors
    ADD CONSTRAINT chk_sensors_auth_kind CHECK (auth_kind IN ('bearer', 'key_bound'));

CREATE TABLE IF NOT EXISTS sensor_keys (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id      UUID NOT NULL,
    sensor_id      UUID NOT NULL,
    thumbprint     VARCHAR(43) NOT NULL,
    public_key     BYTEA NOT NULL,
    alg            VARCHAR(16) NOT NULL DEFAULT 'ed25519',
    status         VARCHAR(16) NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at   TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    revoked_reason VARCHAR(64),
    last_used_at   TIMESTAMPTZ,
    last_used_ip   INET,
    CONSTRAINT fk_sensor_keys_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_sensor_keys_status CHECK (status IN ('pending', 'active', 'revoked')),
    CONSTRAINT chk_sensor_keys_alg CHECK (alg = 'ed25519'),
    CONSTRAINT chk_sensor_keys_public_key CHECK (octet_length(public_key) = 32),
    CONSTRAINT chk_sensor_keys_thumbprint CHECK (thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT chk_sensor_keys_revoked CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

-- A key belongs to one sensor for ever: a thumbprint is never registered twice,
-- even after revocation, so a revoked key can never come back under another
-- sensor or tenant.
CREATE UNIQUE INDEX IF NOT EXISTS ux_sensor_keys_thumbprint ON sensor_keys (thumbprint);
CREATE INDEX IF NOT EXISTS ix_sensor_keys_sensor ON sensor_keys (tenant_id, sensor_id, created_at DESC);

COMMENT ON TABLE sensor_keys IS 'Public keys of key-bound sensors (RFC-052): the RFC 9421 keyid is the RFC 7638 thumbprint.';
COMMENT ON COLUMN sensors.auth_kind IS 'bearer (octs_/rda_ key) or key_bound (Ed25519 key, signed requests; RFC-052).';
