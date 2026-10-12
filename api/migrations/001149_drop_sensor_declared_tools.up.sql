-- Drop sensors.tools, the tools an administrator declared on a sensor.
--
-- The column was set when a sensor was created and went stale: a sensor
-- reports its tools itself (heartbeat tools[], the RFC-033 manifest), and a
-- sensor reporting nine tools still had four declared. It also narrowed
-- dispatch (effective_tools = reported ∩ declared), so tools the sensor had
-- installed after creation never got jobs. The administrator's narrowing is
-- the sensor grant (sensor_grants.tools, RFC-052), which dispatch already
-- enforces. effective_tools becomes the reported installed tools, none for a
-- sensor that never reported (dispatch already read none from such a
-- sensor: command_repository.go sensorDispatchTools).
--
-- Re-adding a stored generated column rewrites the table under an ACCESS
-- EXCLUSIVE lock. sensors holds one row per sensor (tens to hundreds), so
-- the rewrite takes milliseconds.
--
-- expand-contract-ok: contract step; the api of this release neither reads nor writes sensors.tools, and the column is replaced in the same statement
ALTER TABLE sensors
    DROP COLUMN effective_tools,
    DROP COLUMN tools,
    ADD COLUMN effective_tools text[] GENERATED ALWAYS AS (COALESCE(reported_tool_names, '{}'::text[])) STORED;

COMMENT ON COLUMN sensors.effective_tools IS 'Tools dispatch uses: the installed tools the sensor reported, none before its first report (generated). The sensor grant narrows them.';
