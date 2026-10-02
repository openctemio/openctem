-- Bind a federated (SSO/OIDC) user to the stable identity of the IdP that
-- created it, so a verified email at a DIFFERENT IdP cannot take the account
-- over. The AuthProvider enum is coarse — every Okta org and every generic
-- OIDC IdP collapses to 'oidc' — so the provider-match guard alone cannot tell
-- "corp Okta" from "attacker's own Okta". The OIDC issuer (and subject) do.
--
-- Nullable: pre-existing federated users have no recorded issuer; they are
-- bound on their next login (trust-on-first-use) and enforced thereafter.
ALTER TABLE users ADD COLUMN IF NOT EXISTS federated_issuer  TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS federated_subject TEXT;
