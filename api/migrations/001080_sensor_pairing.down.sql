-- Reverts 001075. Pairing requests are dropped; sensors already paired keep
-- their keys (sensor_keys, 001065).
SET lock_timeout = '5s';

CREATE OR REPLACE FUNCTION refuse_admin_only_permission_on_custom_role()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete')
       AND EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'permission % is reserved for the owner and admin roles and cannot be put on a custom role',
            NEW.permission_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DELETE FROM role_permissions WHERE permission_id IN
    ('sensors:pair', 'sensors:approve', 'sensors:grant:narrow', 'sensors:grant:widen', 'sensors:revoke');
DELETE FROM permissions WHERE id IN
    ('sensors:pair', 'sensors:approve', 'sensors:grant:narrow', 'sensors:grant:widen', 'sensors:revoke');

DROP TABLE IF EXISTS sensor_pairings;
ALTER TABLE tenants DROP COLUMN IF EXISTS sensor_bearer_keys_allowed;
