-- Rows a tenant verified for EASM would start admitting SSO users once the
-- column is gone, so they are removed first (they hold no other data).
DELETE FROM verified_domains WHERE purpose = 'easm';
ALTER TABLE verified_domains DROP CONSTRAINT IF EXISTS chk_verified_domains_purpose;
ALTER TABLE verified_domains DROP COLUMN IF EXISTS purpose;
