-- Sensor key binding (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
-- §4.8): whether a bearer-key sensor may bind its own Ed25519 key with an
-- authenticated call (default) or must be re-paired with an administrator's
-- approval. A constant default: no table rewrite on a populated table.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS sensor_key_bind_requires_approval BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tenants.sensor_key_bind_requires_approval IS
    'TRUE: a bearer-key sensor cannot bind its own signing key; it must be re-paired (administrator approval). FALSE (default): self-binding allowed, audited.';
