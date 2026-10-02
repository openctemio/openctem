-- Domain-ownership verification (SSO P1).
-- A tenant proves control of an email domain by publishing a DNS TXT record.
-- A `verified` row is the trust boundary that authorizes SSO JIT auto-join for
-- that domain's users — an IdP proves WHO a user is, a DNS-proven domain proves
-- a tenant may CLAIM that domain's users.
CREATE TABLE IF NOT EXISTS verified_domains (
    id                 UUID PRIMARY KEY,
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain             TEXT NOT NULL,
    verification_token TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    verified_at        TIMESTAMPTZ,
    last_checked_at    TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_verified_domains_tenant_domain UNIQUE (tenant_id, domain)
);

-- Tenant-scoped status lookups (list-by-tenant, gate checks).
CREATE INDEX IF NOT EXISTS idx_verified_domains_tenant_status
    ON verified_domains (tenant_id, status);

-- Supports the background re-verify sweep over verified rows due for a recheck.
CREATE INDEX IF NOT EXISTS idx_verified_domains_recheck
    ON verified_domains (status, last_checked_at);
