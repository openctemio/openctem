DROP TRIGGER IF EXISTS trg_forbid_extra_role_for_break_glass ON admin_users;
DROP FUNCTION IF EXISTS forbid_extra_role_for_break_glass();
DROP TRIGGER IF EXISTS trg_forbid_break_glass_extra_role ON platform_role_assignments;
DROP FUNCTION IF EXISTS forbid_break_glass_extra_role();
