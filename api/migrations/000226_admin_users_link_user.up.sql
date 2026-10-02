-- Migration 000226: platform administrators are user accounts (RFC-022 rev. 2)
--
-- Following Tenable Security Center, a platform administrator is a normal user
-- account with a system-level role: it signs in on the same /login page as
-- everyone else. admin_users keeps the role, the TOTP second factor and the
-- admin audit trail; this column links a human administrator to their users
-- row. Rows without a user_id are API-key identities for the CLI/automation.
ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_user_id
    ON admin_users(user_id) WHERE user_id IS NOT NULL;

-- Like Tenable's Administrator, a platform administrator does not belong to
-- any organization. Enforced in the database so every path that creates a
-- membership (organization creation, invitations, SSO/SAML JIT provisioning,
-- SCIM, future code) is covered, not only the ones the application checks.
CREATE OR REPLACE FUNCTION forbid_platform_admin_membership() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM admin_users WHERE user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'platform administrators cannot be members of an organization'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_forbid_platform_admin_membership ON tenant_members;
CREATE TRIGGER trg_forbid_platform_admin_membership
    BEFORE INSERT OR UPDATE OF user_id ON tenant_members
    FOR EACH ROW EXECUTE FUNCTION forbid_platform_admin_membership();

-- admin_credentials.password_hash / password_changed_at (000225) are no longer
-- read or written: administrators sign in on /login with their account's
-- password. They are dropped in a later release (expand-contract), because
-- pods still on the previous version select them during a rolling deploy.
