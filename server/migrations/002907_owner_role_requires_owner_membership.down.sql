DROP TRIGGER IF EXISTS trg_user_roles_owner_requires_owner_membership ON public.user_roles;
DROP FUNCTION IF EXISTS public.enforce_owner_role_requires_owner_membership();
