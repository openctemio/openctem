-- Per-sensor tool settings (api/docs/architecture/sensors.md, "Tool
-- settings"): what an owner or administrator configured for one tool of one
-- of the organization's own sensors. The values are validated against the
-- tool's settings schema (the "config" of the tool descriptor in the
-- sensor's current manifest); schema_digest is the digest of the schema they
-- were validated against, so a later sensor upgrade that changes the schema
-- is noticed at claim time and the values are validated again.
--
-- The foreign key on (tenant_id, sensor_id) ties every row to a sensor of the
-- same organization: a shared platform sensor (tenant_id NULL) can never hold
-- a row, and deleting the sensor deletes its settings.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS sensor_tool_settings (
    tenant_id     uuid         NOT NULL,
    sensor_id     uuid         NOT NULL,
    tool          varchar(100) NOT NULL,
    "values"      jsonb        NOT NULL DEFAULT '{}'::jsonb,
    schema_digest text         NOT NULL,
    updated_by    uuid,
    updated_at    timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_sensor_tool_settings PRIMARY KEY (sensor_id, tool),
    CONSTRAINT fk_sensor_tool_settings_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_sensor_tool_settings_updated_by FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_sensor_tool_settings_tool CHECK (tool ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
    CONSTRAINT chk_sensor_tool_settings_values CHECK (jsonb_typeof("values") = 'object'),
    CONSTRAINT chk_sensor_tool_settings_digest CHECK (schema_digest ~ '^sha256:[0-9a-f]{64}$')
);

COMMENT ON TABLE sensor_tool_settings IS
    'Per-sensor tool settings, validated against the tool settings schema of the sensor''s current manifest; delivered inside the signed job payload.';

CREATE INDEX IF NOT EXISTS idx_sensor_tool_settings_tenant ON sensor_tool_settings (tenant_id, sensor_id);
