-- Personal dashboard snapshots leave with their owner's membership
-- (docs/architecture/dashboards.md, "Snapshots and refresh").
--
-- A personal snapshot holds figures and finding titles computed for its
-- owner's data scope. When the owner is removed from the organization,
-- suspended or offboarded, those stored results are deleted at once instead
-- of waiting for the refresher to notice. A trigger covers every path that
-- ends a membership (member removal, offboarding, suspension, provisioning
-- rollback). Reactivation needs nothing: the next open computes again.
-- The table is small (one row per opened dashboard): safe on a populated
-- database.

CREATE OR REPLACE FUNCTION dash_snapshots_drop_for_member() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM dash_snapshots
    WHERE tenant_id = OLD.tenant_id AND kind = 'personal' AND owner_user_id = OLD.user_id;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION dash_snapshots_drop_for_member() IS
    'Deletes the personal dashboard snapshots of a member whose membership ended (deleted, suspended or offboarded).';

DROP TRIGGER IF EXISTS trg_tenant_members_snapshots_delete ON tenant_members;
CREATE TRIGGER trg_tenant_members_snapshots_delete
    AFTER DELETE ON tenant_members
    FOR EACH ROW EXECUTE FUNCTION dash_snapshots_drop_for_member();

DROP TRIGGER IF EXISTS trg_tenant_members_snapshots_inactive ON tenant_members;
CREATE TRIGGER trg_tenant_members_snapshots_inactive
    AFTER UPDATE OF status ON tenant_members
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status IS DISTINCT FROM 'active')
    EXECUTE FUNCTION dash_snapshots_drop_for_member();

-- Snapshots of owners who already left before this migration.
DELETE FROM dash_snapshots s
WHERE s.kind = 'personal'
  AND NOT EXISTS (SELECT 1 FROM tenant_members m
                  WHERE m.tenant_id = s.tenant_id AND m.user_id = s.owner_user_id AND m.status = 'active');
