-- The repaired rows stay confirmed (their timeline entries explain why).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_duplicate_has_target;
DROP TRIGGER IF EXISTS trg_findings_reopen_orphaned_duplicate ON findings;
DROP FUNCTION IF EXISTS reopen_orphaned_duplicate();
