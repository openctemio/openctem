-- An SSO domain is claimed by one organization, platform-wide
-- (docs/architecture/sso-authentication.md, "Domain claims are exclusive").
--
-- lapsed_at: when a verified row last lost its DNS proof (verified -> failed).
--   Another organization may verify the domain only 7 days after it. A row
--   that is failed already gets now(), so the 7 days start at this upgrade.
-- claim_conflict: set on every row of a domain that two or more organizations
--   had verified for SSO before this migration. Those rows keep admitting
--   their users (no organization loses access); the platform administrator
--   sees the flag and resolves the conflict. The unique index leaves them out.
--
-- Small table (a few rows per organization); the index build is brief.

ALTER TABLE verified_domains
    ADD COLUMN lapsed_at timestamp with time zone,
    ADD COLUMN claim_conflict boolean NOT NULL DEFAULT false;

UPDATE verified_domains
   SET lapsed_at = now()
 WHERE status = 'failed' AND purpose = 'sso';

UPDATE verified_domains v
   SET claim_conflict = true
 WHERE v.purpose = 'sso'
   AND v.status = 'verified'
   AND v.domain IN (
        SELECT domain
          FROM verified_domains
         WHERE purpose = 'sso' AND status = 'verified'
         GROUP BY domain
        HAVING count(DISTINCT tenant_id) > 1
   );

CREATE UNIQUE INDEX uq_verified_domains_sso_claim
    ON verified_domains (domain)
 WHERE purpose = 'sso' AND status = 'verified' AND NOT claim_conflict;

-- The claim check looks a domain up across organizations.
CREATE INDEX idx_verified_domains_domain ON verified_domains (domain);
