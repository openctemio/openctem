CREATE OR REPLACE FUNCTION update_repository_branch_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;

CREATE OR REPLACE FUNCTION update_repository_component_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  target_asset_id UUID;
BEGIN
  target_asset_id := COALESCE(NEW.asset_id, OLD.asset_id);

  UPDATE asset_repositories SET
    component_count = (SELECT COUNT(*) FROM asset_components WHERE asset_id = target_asset_id),
    vulnerable_component_count = (SELECT COUNT(*) FROM asset_components WHERE asset_id = target_asset_id AND has_known_vulnerabilities = true)
  WHERE asset_id = target_asset_id;

  RETURN COALESCE(NEW, OLD);
END;
$$;
