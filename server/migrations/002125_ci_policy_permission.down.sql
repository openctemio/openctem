-- Back to scans:ci:override being admin-only: custom roles lose it first, so
-- the restored trigger's invariant holds for existing rows too.
DELETE FROM role_permissions rp USING roles r
WHERE rp.role_id = r.id AND r.tenant_id IS NOT NULL AND rp.permission_id = 'scans:ci:override';

CREATE OR REPLACE FUNCTION public.refuse_admin_only_permission_on_custom_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete',
                             'scans:ci:write', 'scans:ci:override',
                             'sensors:pair', 'sensors:approve', 'sensors:grant:narrow',
                             'sensors:grant:widen', 'sensors:revoke')
       AND EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'permission % is reserved for the owner and admin roles and cannot be put on a custom role',
            NEW.permission_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

UPDATE api_keys SET scopes = array_remove(scopes, 'scans:ci:policy') WHERE 'scans:ci:policy' = ANY(scopes);
DELETE FROM role_permissions WHERE permission_id = 'scans:ci:policy';
DELETE FROM permissions WHERE id = 'scans:ci:policy';
