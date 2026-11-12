-- The component and branch count triggers keep the asset_repositories counts
-- in step with asset_components and repository_branches. When an
-- organization is deleted, its assets, components and branches all go in one
-- cascade, and the triggers fired for the components and branches can run
-- after the repository asset row is already gone. Their UPDATE of the
-- repository row then fails the asset_repositories -> assets foreign key
-- ("insert or update on table asset_repositories violates foreign key
-- constraint"), and the whole delete is refused: an organization owning a
-- repository with two or more components or branches could not be deleted.
-- The counts of a repository whose asset is being deleted no longer matter,
-- so the triggers skip it.

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
  WHERE asset_id = target_repo_id
    AND EXISTS (SELECT 1 FROM assets a WHERE a.id = target_repo_id);

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
  WHERE asset_id = target_asset_id
    AND EXISTS (SELECT 1 FROM assets a WHERE a.id = target_asset_id);

  RETURN COALESCE(NEW, OLD);
END;
$$;
