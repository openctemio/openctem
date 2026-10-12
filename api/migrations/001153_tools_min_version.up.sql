-- The oldest tool version the catalog accepts (docs/architecture/tool-availability.md).
-- A sensor that reports an older version still runs the tool; the Tools page
-- marks the tool outdated when every online sensor is below it. NULL: no minimum.
ALTER TABLE tools ADD COLUMN IF NOT EXISTS min_version VARCHAR(50);

COMMENT ON COLUMN tools.min_version IS
    'Oldest tool version the catalog accepts (display and advice; dispatch does not read it). NULL: no minimum.';
