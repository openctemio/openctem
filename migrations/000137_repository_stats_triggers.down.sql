DROP TRIGGER IF EXISTS trg_update_branch_finding_counts ON findings;
DROP TRIGGER IF EXISTS trg_update_repository_branch_count ON repository_branches;
DROP TRIGGER IF EXISTS trg_update_repository_component_count ON asset_components;
DROP FUNCTION IF EXISTS update_branch_finding_counts();
DROP FUNCTION IF EXISTS update_repository_branch_count();
DROP FUNCTION IF EXISTS update_repository_component_count();
