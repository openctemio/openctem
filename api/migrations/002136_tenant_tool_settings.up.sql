-- Organization tool defaults (api/docs/architecture/sensors.md, "Tool
-- settings"): per tool, the values every one of the organization's own
-- sensors runs the tool with, unless the sensor overrides a key in its own
-- settings (sensor_tool_settings). The values are validated against every
-- settings schema the organization's sensors report for the tool;
-- schema_digest is the digest of the reference schema (the newest
-- manifest's) they were saved against. Shared platform sensors never
-- receive them.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS tenant_tool_settings (
    tenant_id     uuid         NOT NULL,
    tool          varchar(100) NOT NULL,
    "values"      jsonb        NOT NULL DEFAULT '{}'::jsonb,
    schema_digest text         NOT NULL,
    updated_by    uuid,
    updated_at    timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_tenant_tool_settings PRIMARY KEY (tenant_id, tool),
    CONSTRAINT fk_tenant_tool_settings_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_tool_settings_updated_by FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_tenant_tool_settings_tool CHECK (tool ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
    CONSTRAINT chk_tenant_tool_settings_values CHECK (jsonb_typeof("values") = 'object'),
    CONSTRAINT chk_tenant_tool_settings_digest CHECK (schema_digest ~ '^sha256:[0-9a-f]{64}$')
);

COMMENT ON TABLE tenant_tool_settings IS
    'Organization tool defaults for its own sensors (a sensor overrides a key in sensor_tool_settings); delivered inside the signed job payload as settings_layers.tenant.';
