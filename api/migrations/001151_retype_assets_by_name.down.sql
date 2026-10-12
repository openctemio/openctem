-- Intentional no-op. The up migration corrects data that was wrong (an asset
-- typed against its own name); restoring the wrong type would re-break it.
-- The old type of every changed row is in the up migration's NOTICE output.
SELECT 1;
