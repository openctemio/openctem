-- The legacy quick scans stay ad hoc (they are quick scans; "Save as scan"
-- restores one as a configuration). Archived scans become visible again,
-- disabled.
-- expand-contract-ok: down migration of 001154; drops only the column it added
ALTER TABLE scans DROP COLUMN IF EXISTS archived_at;
