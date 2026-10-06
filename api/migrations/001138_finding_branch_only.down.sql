DROP TRIGGER IF EXISTS trg_repository_branches_promote_branch_only ON repository_branches;
DROP FUNCTION IF EXISTS repository_branches_promote_branch_only();
DROP FUNCTION IF EXISTS promote_branch_only_findings(UUID, UUID[]);
DROP TRIGGER IF EXISTS trg_findings_mark_branch_only ON findings;
DROP FUNCTION IF EXISTS findings_mark_branch_only();
DROP INDEX IF EXISTS idx_findings_branch_only;
ALTER TABLE findings DROP COLUMN IF EXISTS branch_only;
DROP FUNCTION IF EXISTS branch_counts_as_exposure(UUID);
