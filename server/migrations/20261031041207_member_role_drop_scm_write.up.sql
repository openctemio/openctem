-- The built-in Member role no longer holds integrations:scm:write. The
-- permission is privileged (it decides where stored tokens go); creating or
-- changing an SCM connection already needs integrations:manage, which Member
-- never had, so the grant did nothing except make the role privileged.
DELETE FROM role_permissions
 WHERE role_id = '00000000-0000-0000-0000-000000000003'
   AND permission_id = 'integrations:scm:write';
