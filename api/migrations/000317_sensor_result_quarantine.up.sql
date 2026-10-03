-- Sensor results without a command (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
-- §5.3, owner decision Q6 (a)): the tenant's policy for them, and the
-- quarantine where they wait for a person to accept or discard them.
--
-- Additive: two new tables. Every tenant that exists now gets the "warn"
-- policy (unsolicited reports keep being applied, with limits, plus an audit
-- entry and a metric), because sensors on old SDKs or the v1 fallback cannot
-- name their command. A tenant created later has no row and gets the default,
-- "quarantine".

CREATE TABLE IF NOT EXISTS sensor_result_policies (
    tenant_id               UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    mode                    TEXT NOT NULL DEFAULT 'quarantine',
    allow_advisory_evidence BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by              UUID,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sensor_result_policies_mode CHECK (mode IN ('warn', 'quarantine'))
);

COMMENT ON TABLE sensor_result_policies IS
    'Per-tenant policy for sensor results that name no command (RFC-040 §5.3): warn (apply with limits, audit) or quarantine (store for review). No row = quarantine.';

INSERT INTO sensor_result_policies (tenant_id, mode)
SELECT id, 'warn' FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS sensor_result_quarantine (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- No FK: the item outlives a deleted sensor, so its results can still be
    -- reviewed.
    sensor_id      UUID NOT NULL,
    sensor_type    TEXT NOT NULL DEFAULT '',
    protocol       TEXT NOT NULL,
    route          TEXT NOT NULL,
    report_id      TEXT NOT NULL DEFAULT '',
    segment        INTEGER,
    tool_name      TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL,
    assets_count   INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    -- The CTIS report as JSON; NULL once discarded.
    payload        BYTEA,
    payload_size   INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'pending',
    reviewed_by    UUID,
    reviewed_at    TIMESTAMPTZ,
    result         JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sensor_result_quarantine_protocol CHECK (protocol IN ('v1', 'v2')),
    CONSTRAINT sensor_result_quarantine_status CHECK (status IN ('pending', 'accepted', 'discarded')),
    CONSTRAINT sensor_result_quarantine_reviewed CHECK ((status = 'pending') = (reviewed_at IS NULL))
);

COMMENT ON TABLE sensor_result_quarantine IS
    'Sensor reports that named no command, from a sensor whose role may not push results on its own, held for a person to accept or discard (RFC-040 §5.3).';

-- The review list (newest first per status) and the per-tenant/per-sensor
-- pending caps.
CREATE INDEX IF NOT EXISTS idx_sensor_result_quarantine_tenant_status
    ON sensor_result_quarantine (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sensor_result_quarantine_pending_sensor
    ON sensor_result_quarantine (tenant_id, sensor_id)
    WHERE status = 'pending';
