-- Instance scan zones (docs/rfcs/RFC-100-shared-sensors.md §6.1): private
-- ranges an instance administrator lets shared sensors scan, the shared
-- sensors that serve each zone and the organizations it is assigned to. An
-- organization's internal target goes to a shared sensor only inside a zone
-- assigned to that organization; overlapping ranges of different
-- organizations are told apart by the zone. Written only by the admin
-- console service. Not tenant data: an assignment row names the
-- organization, the zone itself belongs to the instance.
--
-- New tables, a nullable column without a default on commands (no table
-- rewrite) and a CHECK added NOT VALID (validated in the next migration).

CREATE TABLE instance_scan_zones (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        varchar(100) NOT NULL,
    description text NOT NULL DEFAULT '',
    ranges      cidr[] NOT NULL,
    created_by  uuid,
    created_at  timestamp with time zone NOT NULL DEFAULT now(),
    updated_at  timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_instance_scan_zones_name CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    CONSTRAINT chk_instance_scan_zones_description CHECK (length(description) <= 1000),
    CONSTRAINT chk_instance_scan_zones_ranges CHECK (cardinality(ranges) BETWEEN 1 AND 256)
);
CREATE UNIQUE INDEX uq_instance_scan_zones_name ON instance_scan_zones (lower(name));

COMMENT ON TABLE instance_scan_zones IS
    'RFC-100: private ranges shared sensors may scan for the organizations a zone is assigned to';

CREATE TABLE instance_scan_zone_sensors (
    zone_id    uuid NOT NULL REFERENCES instance_scan_zones (id) ON DELETE CASCADE,
    sensor_id  uuid NOT NULL REFERENCES sensors (id) ON DELETE CASCADE,
    created_by uuid,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, sensor_id)
);
CREATE INDEX idx_instance_scan_zone_sensors_sensor ON instance_scan_zone_sensors (sensor_id);

COMMENT ON TABLE instance_scan_zone_sensors IS
    'RFC-100: the shared (instance scope) sensors that serve an instance scan zone';

-- Only a shared sensor serves an instance scan zone.
CREATE FUNCTION instance_scan_zone_sensor_is_shared() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sensors WHERE id = NEW.sensor_id AND scope = 'instance') THEN
        RAISE EXCEPTION 'only a shared sensor serves an instance scan zone' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_instance_scan_zone_sensor_is_shared
    BEFORE INSERT OR UPDATE ON instance_scan_zone_sensors
    FOR EACH ROW EXECUTE FUNCTION instance_scan_zone_sensor_is_shared();

CREATE TABLE instance_scan_zone_tenants (
    zone_id    uuid NOT NULL REFERENCES instance_scan_zones (id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    created_by uuid,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, tenant_id)
);
CREATE INDEX idx_instance_scan_zone_tenants_tenant ON instance_scan_zone_tenants (tenant_id);

COMMENT ON TABLE instance_scan_zone_tenants IS
    'RFC-100: the organizations an instance scan zone is assigned to';

-- The instance scan zone of a shared job that reaches internal addresses.
-- No foreign key: a deleted zone leaves the id, and the job is then never
-- signed (the signer no longer knows the zone).
ALTER TABLE commands ADD COLUMN instance_scan_zone_id uuid;
ALTER TABLE commands ADD CONSTRAINT chk_commands_instance_scan_zone_shared
    CHECK (instance_scan_zone_id IS NULL OR is_platform_job) NOT VALID;

COMMENT ON COLUMN commands.instance_scan_zone_id IS
    'Instance scan zone of a shared job that reaches internal addresses (RFC-100); NULL otherwise';
