DROP INDEX IF EXISTS idx_verified_domains_domain;
DROP INDEX IF EXISTS uq_verified_domains_sso_claim;

ALTER TABLE verified_domains
    DROP COLUMN IF EXISTS claim_conflict,
    DROP COLUMN IF EXISTS lapsed_at;
