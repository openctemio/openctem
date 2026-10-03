-- RFC-043 P0 (interim cross-tool auto-resolve guard).
--
-- findings.tool_name is the FIRST tool that reported a finding and is never
-- overwritten; findings.scan_id is the LAST sighting. Default-branch
-- auto-resolve keyed on tool_name, so a finding two tools report was closed by
-- whichever tool missed it although the other still saw it. last_seen_tool is
-- the tool of the last sighting (written with scan_id); auto-resolve lets only
-- that tool close the finding. NULL (rows written before this migration) falls
-- back to tool_name, the previous behavior, until the next sighting fills it.
-- Interim: RFC-043 P2 moves lifecycle to per-tool sightings.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen_tool VARCHAR(100);

COMMENT ON COLUMN findings.last_seen_tool IS
    'Tool of the last sighting (written with scan_id). Auto-resolve closes a finding only for this tool; NULL falls back to tool_name.';
