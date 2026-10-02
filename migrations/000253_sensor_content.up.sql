-- Scanner content (docs/rfcs/RFC-031-managed-sensor-updates.md): the data a
-- sensor's tools scan with (trivy DB, nuclei templates, semgrep rules): the
-- tenant's content policy and the refresh_content command. What a sensor
-- reports is stored inside sensors.reported_tools (the sensor_reported_capabilities migration: each tool's
-- "content" member), so no column is added here.
--
-- Additive: a new table, one more allowed command type, an index.

-- One content policy per tenant: refresh interval, and per content a maximum
-- age, a pinned version and (semgrep) rulesets. Never a content source:
-- sources are the sensor host's configuration.
CREATE TABLE IF NOT EXISTS sensor_content_policies (
    tenant_id  UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    policy     JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sensor_content_policies_policy_object CHECK (jsonb_typeof(policy) = 'object')
);

COMMENT ON TABLE sensor_content_policies IS
    'Per-tenant scanner content policy (RFC-031): max age, pinned versions. No content sources.';

ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_command_type;
ALTER TABLE commands ADD CONSTRAINT chk_command_type
    CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync', 'update_tools', 'run_tool', 'validate', 'refresh_content'));

-- Dedup lookup: at most one open refresh_content per sensor.
CREATE INDEX IF NOT EXISTS idx_commands_open_refresh_content
    ON commands (tenant_id, sensor_id)
    WHERE type = 'refresh_content' AND status IN ('pending', 'acknowledged', 'running');
