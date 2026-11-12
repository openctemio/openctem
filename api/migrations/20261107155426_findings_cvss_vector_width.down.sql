-- Keeps the wider column: narrowing it back to 100 characters would cut the
-- CVSS vectors stored since the up migration, and the code before it reads
-- and writes the wider column unchanged. Nothing to undo.
SELECT 1;
