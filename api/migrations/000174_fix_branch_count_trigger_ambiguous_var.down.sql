-- Restore the original (buggy) function body from migration 000137.
CREATE OR REPLACE FUNCTION update_repository_branch_count()
RETURNS TRIGGER AS $$
DECLARE
  repo_id UUID;
BEGIN
  repo_id := COALESCE(NEW.repository_id, OLD.repository_id);

  UPDATE asset_repositories SET
    branch_count = (SELECT COUNT(*) FROM repository_branches WHERE repository_id = repo_id),
    protected_branch_count = (SELECT COUNT(*) FROM repository_branches WHERE repository_id = repo_id AND is_protected = true)
  WHERE asset_id = repo_id;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
