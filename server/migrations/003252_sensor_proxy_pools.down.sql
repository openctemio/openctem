CREATE OR REPLACE FUNCTION public.refuse_admin_only_permission_on_custom_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete',
                             'scans:ci:write',
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

UPDATE api_keys SET scopes = array_remove(array_remove(array_remove(scopes,
    'sensors:egress:read'), 'sensors:egress:write'), 'sensors:egress:delete')
WHERE scopes && ARRAY['sensors:egress:read', 'sensors:egress:write', 'sensors:egress:delete']::text[];
DELETE FROM role_permissions WHERE permission_id IN ('sensors:egress:read', 'sensors:egress:write', 'sensors:egress:delete');
DELETE FROM permissions WHERE id IN ('sensors:egress:read', 'sensors:egress:write', 'sensors:egress:delete');

DROP TABLE IF EXISTS proxy_sensor_assignments;
DROP TABLE IF EXISTS proxy_endpoints;
DROP TABLE IF EXISTS proxy_pools;
