-- Scope materialisation follows every source write in the same transaction
-- (RFC-050 W6; research 21b H6 / L-12, M-2, M-4, L-16).
--
-- user_accessible_assets used to be refreshed by the application after the
-- source write committed (an error was only logged), and not at all when an
-- access group was deactivated or deleted, when a scope rule was deactivated
-- or deleted, or when a group's asset was unassigned through the ownership
-- path. A deactivated group kept granting its assets indefinitely.
--
-- These triggers make the database keep the materialisation in step with its
-- sources, inside the writing transaction, whatever code path writes:
--
--   asset_owners (group rows)    INSERT  -> members gain the asset
--                                DELETE  -> members lose it unless another
--                                           active group or a grant gives it
--   group_members                DELETE  -> the user loses the group's assets
--                                           (same exception)
--   groups.is_active             change  -> every member's scope recomputed
--   groups                       DELETE  -> the group's asset rows are removed
--                                           first, so the members lose them
--   group_asset_scope_rules      DELETE / deactivate -> the rule's
--                                           auto-assigned rows are removed
--                                           (instead of ON DELETE SET NULL
--                                           orphaning them)
--
-- The application's own refresh calls stay; they are idempotent.
-- Live-data impact: triggers only; no table is rewritten. A final full
-- refresh repairs rows left behind by the old behaviour.

CREATE OR REPLACE FUNCTION trg_asset_owners_scope_sync()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.group_id IS NOT NULL THEN
            PERFORM refresh_access_for_asset_assign(NEW.group_id, NEW.asset_id, NEW.ownership_type);
        END IF;
        RETURN NEW;
    END IF;
    -- DELETE
    IF OLD.group_id IS NOT NULL THEN
        PERFORM refresh_access_for_asset_unassign(OLD.group_id, OLD.asset_id);
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS asset_owners_scope_sync ON asset_owners;
CREATE TRIGGER asset_owners_scope_sync
    AFTER INSERT OR DELETE ON asset_owners
    FOR EACH ROW EXECUTE FUNCTION trg_asset_owners_scope_sync();

CREATE OR REPLACE FUNCTION trg_group_members_scope_sync()
RETURNS trigger AS $$
BEGIN
    PERFORM refresh_access_for_member_remove(OLD.group_id, OLD.user_id);
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS group_members_scope_sync ON group_members;
CREATE TRIGGER group_members_scope_sync
    AFTER DELETE ON group_members
    FOR EACH ROW EXECUTE FUNCTION trg_group_members_scope_sync();

CREATE OR REPLACE FUNCTION trg_groups_active_scope_sync()
RETURNS trigger AS $$
DECLARE
    m RECORD;
BEGIN
    FOR m IN SELECT gm.user_id FROM group_members gm WHERE gm.group_id = NEW.id LOOP
        PERFORM refresh_access_for_user(NEW.tenant_id, m.user_id);
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS groups_active_scope_sync ON groups;
CREATE TRIGGER groups_active_scope_sync
    AFTER UPDATE OF is_active ON groups
    FOR EACH ROW
    WHEN (OLD.is_active IS DISTINCT FROM NEW.is_active)
    EXECUTE FUNCTION trg_groups_active_scope_sync();

-- Before a group goes, remove its asset rows while its members still exist:
-- each removal drops the members' access through asset_owners_scope_sync.
CREATE OR REPLACE FUNCTION trg_groups_delete_scope_sync()
RETURNS trigger AS $$
BEGIN
    DELETE FROM asset_owners WHERE group_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS groups_delete_scope_sync ON groups;
CREATE TRIGGER groups_delete_scope_sync
    BEFORE DELETE ON groups
    FOR EACH ROW EXECUTE FUNCTION trg_groups_delete_scope_sync();

-- A scope rule that is deleted or deactivated takes its auto-assigned rows
-- with it (they would otherwise keep granting access).
CREATE OR REPLACE FUNCTION trg_scope_rule_scope_sync()
RETURNS trigger AS $$
BEGIN
    DELETE FROM asset_owners WHERE scope_rule_id = OLD.id;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scope_rule_delete_scope_sync ON group_asset_scope_rules;
CREATE TRIGGER scope_rule_delete_scope_sync
    BEFORE DELETE ON group_asset_scope_rules
    FOR EACH ROW EXECUTE FUNCTION trg_scope_rule_scope_sync();

DROP TRIGGER IF EXISTS scope_rule_deactivate_scope_sync ON group_asset_scope_rules;
CREATE TRIGGER scope_rule_deactivate_scope_sync
    AFTER UPDATE OF is_active ON group_asset_scope_rules
    FOR EACH ROW
    WHEN (OLD.is_active AND NOT NEW.is_active)
    EXECUTE FUNCTION trg_scope_rule_scope_sync();

-- Repair what the old behaviour left behind: rows of deactivated rules, and
-- scope rows granted by deactivated groups.
DELETE FROM asset_owners ao
USING group_asset_scope_rules r
WHERE ao.scope_rule_id = r.id AND NOT r.is_active;

SELECT refresh_user_accessible_assets();
