-- The owner system role in user_roles requires the owner label on the
-- member's tenant_members row. The label is changed only by the membership
-- routes and ownership transfer; the Roles API no longer grants system roles.
-- This trigger is the database backstop: a direct or future write cannot give
-- anyone the owner role without the owner membership.
--
-- It checks new writes only (INSERT, and UPDATE of the identity columns).
-- Rows that already break the rule are NOT touched; list them with the report
-- query in api/docs/architecture/authorization-matrix.md ("Owner role without
-- the owner membership") and decide per organization.

CREATE OR REPLACE FUNCTION public.enforce_owner_role_requires_owner_membership() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM tenant_members tm
        WHERE tm.user_id = NEW.user_id
          AND tm.tenant_id = NEW.tenant_id
          AND tm.role = 'owner'
    ) THEN
        RAISE EXCEPTION 'the owner role requires the owner membership (user %, tenant %)', NEW.user_id, NEW.tenant_id
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'user_roles_owner_requires_owner_membership';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_user_roles_owner_requires_owner_membership ON public.user_roles;
CREATE TRIGGER trg_user_roles_owner_requires_owner_membership
    BEFORE INSERT OR UPDATE OF user_id, tenant_id, role_id ON public.user_roles
    FOR EACH ROW
    WHEN (NEW.role_id = '00000000-0000-0000-0000-000000000001'::uuid)
    EXECUTE FUNCTION public.enforce_owner_role_requires_owner_membership();
