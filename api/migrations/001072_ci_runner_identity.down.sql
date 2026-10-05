-- Reverses 001053_ci_runner_identity.up.sql.

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

DELETE FROM role_permissions WHERE permission_id IN ('scans:ci:read', 'scans:ci:write', 'scans:ci:override');
DELETE FROM permissions WHERE id IN ('scans:ci:read', 'scans:ci:write', 'scans:ci:override');

DROP TABLE IF EXISTS ci_gate_overrides;
DROP TABLE IF EXISTS ci_gate_policies;
DROP TABLE IF EXISTS ci_oidc_replay;
DROP TABLE IF EXISTS ci_run_findings;
DROP TABLE IF EXISTS ci_runs;
DROP TABLE IF EXISTS ci_trust_configs;
