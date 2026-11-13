-- Per-domain just-in-time provisioning (RFC-058): an organization with several
-- SSO domains decides, per domain, whether its SSO admits new people and with
-- which role (viewer or member; administrators are never provisioned).
ALTER TABLE verified_domains
    ADD COLUMN jit_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN jit_role text NULL,
    ADD CONSTRAINT chk_verified_domains_jit_role CHECK (jit_role IS NULL OR jit_role IN ('viewer', 'member'));

COMMENT ON COLUMN verified_domains.jit_enabled IS
    'SSO may admit new people with an address on this domain (just-in-time provisioning).';
COMMENT ON COLUMN verified_domains.jit_role IS
    'Role of people admitted through this domain (viewer or member); NULL uses the identity provider default.';
