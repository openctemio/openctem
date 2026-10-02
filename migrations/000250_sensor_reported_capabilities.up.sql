-- Sensor-reported capabilities (docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md
-- §4.3.1). A sensor reports on its heartbeat which tools it really has, the
-- capabilities it serves and how many jobs it runs at once. Dispatch uses the
-- EFFECTIVE values: what the sensor reports, narrowed by the administrator's
-- settings (tools, capabilities, max_concurrent_jobs), which can never widen
-- it. A sensor that never reported keeps the administrator's values.
--
-- Additive: nullable columns, a function and generated columns. NULL in a
-- reported_* column means "not reported" (an SDK from before the report).

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS reported_tools jsonb,
    ADD COLUMN IF NOT EXISTS reported_tool_names text[],
    ADD COLUMN IF NOT EXISTS reported_capabilities text[],
    ADD COLUMN IF NOT EXISTS reported_max_jobs integer,
    ADD COLUMN IF NOT EXISTS reported_os varchar(32),
    ADD COLUMN IF NOT EXISTS reported_arch varchar(32),
    ADD COLUMN IF NOT EXISTS reported_at timestamptz;

-- The narrowing rule, the same as Sensor.EffectiveTools / EffectiveCapabilities
-- (pkg/domain/sensor/reported.go): not reported → declared; nothing declared →
-- reported; else reported ∩ declared, in reported order.
CREATE OR REPLACE FUNCTION sensor_effective_list(declared text[], reported text[])
RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN reported IS NULL THEN COALESCE(declared, '{}'::text[])
        WHEN COALESCE(cardinality(declared), 0) = 0 THEN reported
        ELSE ARRAY(
            SELECT r.v FROM unnest(reported) WITH ORDINALITY AS r(v, i)
            WHERE r.v = ANY(declared)
            ORDER BY r.i
        )
    END
$$;

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS effective_tools text[]
        GENERATED ALWAYS AS (sensor_effective_list(tools, reported_tool_names)) STORED,
    ADD COLUMN IF NOT EXISTS effective_capabilities text[]
        GENERATED ALWAYS AS (sensor_effective_list(capabilities, reported_capabilities)) STORED,
    ADD COLUMN IF NOT EXISTS effective_max_jobs integer
        GENERATED ALWAYS AS (
            CASE
                WHEN reported_max_jobs IS NULL OR reported_max_jobs <= 0 THEN max_concurrent_jobs
                WHEN max_concurrent_jobs IS NULL OR max_concurrent_jobs <= 0 THEN reported_max_jobs
                ELSE LEAST(reported_max_jobs, max_concurrent_jobs)
            END
        ) STORED;

COMMENT ON COLUMN sensors.reported_tools IS 'Tool inventory the sensor last reported: [{name, version, installed}], names in the tool catalog only. Untrusted, sanitized at ingest. NULL: never reported.';
COMMENT ON COLUMN sensors.reported_tool_names IS 'Names of the installed tools in reported_tools (the dispatch input). NULL: never reported.';
COMMENT ON COLUMN sensors.reported_capabilities IS 'Capabilities the sensor last reported (known names only). NULL: never reported.';
COMMENT ON COLUMN sensors.reported_max_jobs IS 'Concurrency the sensor last reported, 1..100. NULL: never reported.';
COMMENT ON COLUMN sensors.reported_os IS 'Operating system the sensor reported (display only).';
COMMENT ON COLUMN sensors.reported_arch IS 'Architecture the sensor reported (display only).';
COMMENT ON COLUMN sensors.reported_at IS 'When the capability report was last written.';
COMMENT ON COLUMN sensors.effective_tools IS 'Tools dispatch uses: reported installed tools narrowed by tools (generated).';
COMMENT ON COLUMN sensors.effective_capabilities IS 'Capabilities dispatch and the command poll use: reported narrowed by capabilities (generated).';
COMMENT ON COLUMN sensors.effective_max_jobs IS 'Capacity dispatch uses: min(reported_max_jobs, max_concurrent_jobs) (generated).';
