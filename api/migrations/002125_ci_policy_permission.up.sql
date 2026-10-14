-- scans:ci:policy (RFC-051): gate policies and coverage expectations get their
-- own permission, so an AppSec custom role can run the CI gate without the
-- admin-only scans:ci:write (trust configurations and code host connections,
-- which issue or admit upload credentials). scans:ci:override (break-glass,
-- with step-up and an alert to every administrator) stops being admin-only so
-- the same role can carry it. The owner and admin roles get the new
-- permission; nothing else changes hands.

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
VALUES
    ('scans:ci:policy', 'scans', 'Manage CI Gate Policies',
     'Create, change and delete CI gate policies and coverage expectations (loosening needs step-up)', true, now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (id, role_id, permission_id, created_at)
SELECT uuid_generate_v7(), r.id, 'scans:ci:policy', now()
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
  AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = 'scans:ci:policy');

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
