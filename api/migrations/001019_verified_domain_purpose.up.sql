-- What a verified domain is trusted for (research/22 P0-10, owner decision
-- E6; docs/architecture/easm.md, docs/architecture/user-onboarding.md).
--
-- Tenants can now verify a domain themselves for EASM. That must not by
-- itself admit SSO JIT or SCIM users of the domain, so each row carries a
-- purpose: 'sso' (set up by a platform administrator: admits users and
-- counts for EASM) or 'easm' (tenant self-service: attribution only).
-- Every existing row was made in the admin console, so they are 'sso' and
-- keep admitting exactly whom they admit today.
ALTER TABLE verified_domains
    ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'sso';

ALTER TABLE verified_domains DROP CONSTRAINT IF EXISTS chk_verified_domains_purpose;
ALTER TABLE verified_domains
    ADD CONSTRAINT chk_verified_domains_purpose CHECK (purpose IN ('easm', 'sso'));
