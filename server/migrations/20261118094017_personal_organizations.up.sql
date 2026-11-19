-- The personal organization at sign-up (docs/architecture/user-onboarding.md,
-- "Personal organization at sign-up"). An account created by self-service
-- sign-up while the switch is on is marked pending; at a sign-in after its
-- address is verified the platform makes its organization once, in the
-- transaction that locks this row (two sign-ins at once make one), and
-- settles the mark. A new, empty table: no backfill, no lock on live data.
CREATE TABLE IF NOT EXISTS personal_organizations (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    status varchar(16) NOT NULL DEFAULT 'pending',
    -- The organization made; NULL once it is deleted (it is never made
    -- again).
    tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
    -- Reduced forms kept for the creation rate bounds: the registrable
    -- e-mail domain and the client network prefix (/24, /48).
    email_domain varchar(253),
    ip_prefix cidr,
    reserved_at timestamptz NOT NULL DEFAULT now(),
    settled_at timestamptz,
    CONSTRAINT chk_personal_organizations_status CHECK (status IN ('pending', 'created', 'skipped')),
    CONSTRAINT chk_personal_organizations_settled CHECK ((status = 'pending') = (settled_at IS NULL))
);
-- The rate bounds count recent creations by domain and by prefix.
CREATE INDEX IF NOT EXISTS idx_personal_organizations_created
    ON personal_organizations (settled_at) WHERE status = 'created';
-- The foreign key's ON DELETE SET NULL looks rows up by tenant.
CREATE INDEX IF NOT EXISTS idx_personal_organizations_tenant
    ON personal_organizations (tenant_id) WHERE tenant_id IS NOT NULL;
