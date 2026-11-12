-- SAML IdP certificate expiry alerts: the tightest notice (30, 7, 1 or 0 days)
-- already sent to the owners for the current certificate. NULL means none yet;
-- the API resets it whenever the certificate changes. Nullable, no backfill.
ALTER TABLE saml_providers
    ADD COLUMN IF NOT EXISTS cert_expiry_notice_days smallint
        CHECK (cert_expiry_notice_days IS NULL OR cert_expiry_notice_days BETWEEN 0 AND 30);
