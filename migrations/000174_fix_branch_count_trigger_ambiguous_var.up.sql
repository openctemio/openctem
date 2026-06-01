-- Fix a real bug in the repository branch-count trigger (migration 000137).
--
-- update_repository_branch_count() declared a PL/pgSQL variable named `repo_id`,
-- which collides with the `repo_id` COLUMN on repository_branches inside the
-- subquery `... FROM repository_branches WHERE repository_id = repo_id`. With
-- PL/pgSQL's default variable_conflict=error, every INSERT/DELETE/UPDATE OF
-- is_protected on repository_branches raised:
--   ERROR: column reference "repo_id" is ambiguous (42702)
-- That fires on branch creation, so ingest's branch upsert failed (it logs +
-- continues), leaving findings with branch_id=NULL and branch tracking broken.
--
-- Fix: rename the variable to target_repo_id (mirrors the sibling
-- update_repository_component_count function, which already uses target_asset_id).

CREATE OR REPLACE FUNCTION update_repository_branch_count()
RETURNS TRIGGER AS $$
DECLARE
  target_repo_id UUID;
BEGIN
  target_repo_id := COALESCE(NEW.repository_id, OLD.repository_id);

  UPDATE asset_repositories SET
    branch_count = (SELECT COUNT(*) FROM repository_branches WHERE repository_id = target_repo_id),
    protected_branch_count = (SELECT COUNT(*) FROM repository_branches WHERE repository_id = target_repo_id AND is_protected = true)
  WHERE asset_id = target_repo_id;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
