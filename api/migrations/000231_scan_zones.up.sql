-- Migration 000231: scan zones (RFC-023 Phase 1).
-- Design: docs/rfcs/RFC-023-scan-zones-and-scanners.md (D3-D6, D16, §5, §11);
-- architecture: docs/architecture/scan-zones.md.
--
-- A scan zone is a tenant-owned set of address ranges and the sensors that
-- may scan them. Trigger-time routing pins each job to a healthy sensor of the
-- narrowest matching zone and stamps the zone on the command; the claim query
-- then hands a zone-stamped command only to a sensor assigned to that zone.
--
-- Additive only: two new tables, one nullable column, one unique constraint,
-- three permissions. scan_networks (RFC-023 §5) is Phase 4 and not created.

-- Composite key target so scan_zone_sensors can enforce, in SQL, that a zone
-- and a sensor belong to the same tenant. Platform sensors (tenant_id NULL)
-- can never match it.
ALTER TABLE sensors ADD CONSTRAINT uq_sensors_tenant_id_id UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS scan_zones (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_default  BOOLEAN NOT NULL DEFAULT FALSE,
    -- Normalised by the application (masked, sorted, no contained prefixes,
    -- nothing in the deny list); the cidr type rejects host bits on its own.
    ranges      CIDR[] NOT NULL DEFAULT '{}',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_scan_zones_tenant_id_id UNIQUE (tenant_id, id),
    CONSTRAINT chk_scan_zones_name CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    CONSTRAINT chk_scan_zones_description CHECK (length(description) <= 1000),
    CONSTRAINT chk_scan_zones_ranges_bounded CHECK (cardinality(ranges) <= 256),
    CONSTRAINT chk_scan_zones_ranges_present CHECK (is_default OR cardinality(ranges) > 0)
);

COMMENT ON TABLE scan_zones IS 'RFC-023: tenant address ranges and the sensors that may scan them';

CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_zones_tenant_name ON scan_zones (tenant_id, lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_zones_tenant_default ON scan_zones (tenant_id) WHERE is_default;

CREATE TABLE IF NOT EXISTS scan_zone_sensors (
    tenant_id   UUID NOT NULL,
    zone_id     UUID NOT NULL,
    sensor_id   UUID NOT NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_scan_zone_sensors PRIMARY KEY (zone_id, sensor_id),
    -- Same-tenant membership is a schema rule, not a handler check.
    CONSTRAINT fk_scan_zone_sensors_zone FOREIGN KEY (tenant_id, zone_id)
        REFERENCES scan_zones (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_zone_sensors_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE
);

COMMENT ON TABLE scan_zone_sensors IS 'RFC-023: which sensors serve which scan zone (same tenant enforced by composite FKs)';

CREATE INDEX IF NOT EXISTS idx_scan_zone_sensors_sensor ON scan_zone_sensors (sensor_id);

-- The zone a command was routed to. Deliberately no foreign key: a zone is
-- only deleted when none of its commands are active, and a dangling id on a
-- historical command keeps the claim predicate failing closed (no sensor is
-- a member of a deleted zone) instead of releasing the job to every sensor,
-- which ON DELETE SET NULL would do.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS scan_zone_id UUID;

CREATE INDEX IF NOT EXISTS idx_commands_scan_zone_active
    ON commands (scan_zone_id)
    WHERE scan_zone_id IS NOT NULL AND status IN ('pending', 'acknowledged', 'running');

-- Permissions (RFC-023 D16), in the sensors module: owner and admin manage
-- zones, members and viewers read them.
INSERT INTO permissions (id, module_id, name, description) VALUES
    ('sensors:zones:read', 'sensors', 'View Scan Zones', 'View scan zones, their ranges, assigned sensors and coverage'),
    ('sensors:zones:write', 'sensors', 'Manage Scan Zones', 'Create and edit scan zones and assign sensors to them'),
    ('sensors:zones:delete', 'sensors', 'Delete Scan Zones', 'Delete scan zones')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.id
FROM permissions p
CROSS JOIN (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid),
    ('00000000-0000-0000-0000-000000000002'::uuid)
) AS r(role_id)
WHERE p.id IN ('sensors:zones:read', 'sensors:zones:write', 'sensors:zones:delete')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'sensors:zones:read'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000003'::uuid),
    ('00000000-0000-0000-0000-000000000004'::uuid)
) AS r(role_id)
ON CONFLICT DO NOTHING;
