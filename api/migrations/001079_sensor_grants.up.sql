-- =============================================================================
-- Migration 001079: per-sensor grants (RFC-052 §5)
-- =============================================================================
-- One row per sensor: what that sensor may do, checked by the platform on
-- every poll, claim, unsolicited result and heartbeat action. NULL in a list
-- column means "no limit from the grant" on that dimension; an empty array
-- means "nothing".
--
-- Every sensor has exactly one grant:
-- 1. Existing sensors get the broad legacy grant at trust level "trusted", in
--    one statement, so nothing changes for them (the console flags it).
-- 2. A sensor inserted later gets the narrowest default (profile
--    internal-network-scanner at trust level "new": passive work only, no
--    credentials, no push ingest) from a trigger, whatever code path created
--    it; the pairing approval and the create form then set the chosen
--    profile in the same request. Platform sensors keep the legacy grant.
--
-- Live-database safety: a new table; the backfill inserts one small row per
-- sensor (a few hundred at most); the trigger only adds an insert to sensor
-- creation.
-- =============================================================================

SET lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS sensor_grants (
    sensor_id         UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    profile           VARCHAR(96) NOT NULL,
    trust_level       VARCHAR(16) NOT NULL DEFAULT 'new',
    job_types         TEXT[],
    zone_ids          UUID[],
    tools             TEXT[],
    capabilities      TEXT[],
    tier_ceiling      SMALLINT NOT NULL DEFAULT 0,
    target_network    VARCHAR(16) NOT NULL DEFAULT 'any',
    target_cidrs      TEXT[],
    target_domains    TEXT[],
    allow_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    allow_push_ingest BOOLEAN NOT NULL DEFAULT FALSE,
    remote_actions    TEXT[] NOT NULL DEFAULT '{}',
    version           INTEGER NOT NULL DEFAULT 1,
    updated_by        UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_sensor_grants_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_sensor_grants_trust CHECK (trust_level IN ('new', 'trusted')),
    CONSTRAINT chk_sensor_grants_tier CHECK (tier_ceiling BETWEEN 0 AND 2),
    CONSTRAINT chk_sensor_grants_network CHECK (target_network IN ('any', 'public', 'none')),
    CONSTRAINT chk_sensor_grants_version CHECK (version >= 1),
    CONSTRAINT chk_sensor_grants_profile CHECK (profile ~ '^[a-z][a-z0-9-]*(:[a-z0-9._-]{1,64})?$')
);

CREATE INDEX IF NOT EXISTS ix_sensor_grants_tenant ON sensor_grants (tenant_id, profile);

COMMENT ON TABLE sensor_grants IS
    'Per-sensor grant (RFC-052 §5): job types, zones, tools, capabilities, tier ceiling, target network and scope, credentials, push ingest, remote actions, trust level. NULL list = no limit; empty = nothing.';

-- 1. Backfill: every sensor that exists now keeps what it could do.
INSERT INTO sensor_grants (sensor_id, tenant_id, profile, trust_level, tier_ceiling, target_network,
                           allow_credentials, allow_push_ingest, remote_actions)
SELECT s.id, s.tenant_id, 'legacy-broad', 'trusted', 2, 'any', TRUE, TRUE,
       ARRAY['diagnostics', 'rotate_key', 'update']
FROM sensors s
ON CONFLICT (sensor_id) DO NOTHING;

-- 2. Every later sensor starts with the narrowest default.
CREATE OR REPLACE FUNCTION sensor_grants_default()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.is_platform_sensor THEN
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, trust_level, tier_ceiling, target_network,
                                   allow_credentials, allow_push_ingest, remote_actions)
        VALUES (NEW.id, NEW.tenant_id, 'legacy-broad', 'trusted', 2, 'any', TRUE, TRUE,
                ARRAY['diagnostics', 'rotate_key', 'update'])
        ON CONFLICT (sensor_id) DO NOTHING;
    ELSE
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, trust_level, job_types, tier_ceiling, target_network)
        VALUES (NEW.id, NEW.tenant_id, 'internal-network-scanner', 'new', ARRAY['scan', 'validate'], 1, 'any')
        ON CONFLICT (sensor_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trigger_sensor_grants_default ON sensors;
CREATE TRIGGER trigger_sensor_grants_default
    AFTER INSERT ON sensors
    FOR EACH ROW EXECUTE FUNCTION sensor_grants_default();
