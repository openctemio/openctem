-- What a host name resolves to from where each of the organization's sensors
-- sits (its vantage point). A name may resolve to public addresses for the
-- platform and to private ones only inside the company network (split-horizon
-- DNS): the router reads these answers so that a name only an internal sensor
-- can resolve routes to that sensor's scan zone instead of being refused as
-- "does not resolve". Design: docs/architecture/scan-zones.md "Vantage
-- resolution".
--
-- Written only from reports bound to a command of a tenant sensor: the
-- observer is the command's sensor and its zone, never a value from the
-- report. An answer is not a scope grant: a private address still has to be
-- in scope and inside a scan zone before anything is dispatched to it.
--
-- Live impact: a new, empty table; no lock on existing tables.

CREATE TABLE IF NOT EXISTS name_resolutions (
    tenant_id    uuid         NOT NULL,
    name         varchar(253) NOT NULL,
    sensor_id    uuid         NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    zone_id      uuid,
    addrs        text[]       NOT NULL,
    observed_at  timestamptz  NOT NULL,
    CONSTRAINT pk_name_resolutions PRIMARY KEY (tenant_id, name, sensor_id),
    CONSTRAINT fk_name_resolutions_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT chk_name_resolutions_name CHECK (name = lower(name) AND length(name) > 0),
    CONSTRAINT chk_name_resolutions_addrs CHECK (cardinality(addrs) BETWEEN 1 AND 16)
);

CREATE INDEX IF NOT EXISTS idx_name_resolutions_sensor ON name_resolutions (sensor_id);

COMMENT ON TABLE name_resolutions IS
    'Per-sensor DNS answers of host names (vantage points): the observer is the bound command''s sensor and zone. Routing input only, never a scope grant.';
