-- Restore sensors.tools (empty: the declared lists are not recoverable, and
-- an empty list narrows nothing) and the effective_tools expression that
-- narrows the reported tools by it.
ALTER TABLE sensors
    DROP COLUMN effective_tools,
    ADD COLUMN tools text[] DEFAULT '{}'::text[],
    ADD COLUMN effective_tools text[] GENERATED ALWAYS AS (public.sensor_effective_list(tools, reported_tool_names)) STORED;

COMMENT ON COLUMN sensors.effective_tools IS 'Tools dispatch uses: reported installed tools narrowed by tools (generated).';
