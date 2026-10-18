-- findings.duplicate_of references findings(id) ON DELETE SET NULL. With no
-- index on the referencing column, every deleted finding makes the foreign key
-- action scan the whole findings table for rows pointing at it, so deleting a
-- few hundred findings of a large tenant takes seconds to minutes. Partial:
-- almost no finding is a duplicate.
--
-- CONCURRENTLY keeps the table writable while it builds; it cannot run in a
-- transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_duplicate_of
    ON findings (duplicate_of)
    WHERE duplicate_of IS NOT NULL;
