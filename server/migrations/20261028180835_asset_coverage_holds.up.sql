-- Coverage holds (docs/rfcs/RFC-093-asset-coverage.md): one row per tenant
-- and capability counting how many of its coverage runs in a row ended with
-- no sensor taking the work (NO_SENSOR). From the third, the capability is
-- paused (readiness reason not_claimed) until the tenant's sensor fleet
-- changes (fingerprint: a hash of the sensors, grants, zones and shared
-- access the claim depends on, computed and compared on the server only) or
-- until probe_at, when one run probes again with a doubled wait after it.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS asset_coverage_holds (
    tenant_id        uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    capability       varchar(64) NOT NULL,
    unclaimed_streak smallint    NOT NULL DEFAULT 0,
    fingerprint      varchar(64) NOT NULL DEFAULT '',
    probe_at         timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_coverage_holds PRIMARY KEY (tenant_id, capability),
    CONSTRAINT chk_asset_coverage_holds_streak CHECK (unclaimed_streak >= 0)
);

COMMENT ON TABLE asset_coverage_holds IS
    'RFC-093: consecutive coverage runs no sensor took, per tenant and capability; paused from the third until the sensor fleet changes or the probe time.';
