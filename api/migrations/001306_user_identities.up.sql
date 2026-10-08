-- Federated accounts are keyed on the identity provider's user id, not on the
-- email address. One row per (issuer, subject) an account signs in with.
--
-- scope_tenant_id says who may assert the identity:
--   NULL  the issuer signs it with keys only the issuer holds (an OIDC id_token
--         checked against the issuer's published keys, or a social provider's
--         API), so the pair means the same person platform-wide;
--   set   a SAML assertion: the organization configures the IdP certificate,
--         so the pair is trusted only inside that organization. Another
--         organization cannot claim it by configuring the same entity id.
CREATE TABLE user_identities (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer          text NOT NULL CHECK (issuer <> '' AND length(issuer) <= 2048),
    subject         text NOT NULL CHECK (subject <> '' AND length(subject) <= 1024),
    scope_tenant_id uuid NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz NULL
);

-- One account per identity.
CREATE UNIQUE INDEX uq_user_identities_subject
    ON user_identities (issuer, subject, scope_tenant_id) NULLS NOT DISTINCT;
-- One subject per issuer on an account: a second subject from the same issuer
-- presenting the account's email is a takeover attempt, never a second binding.
CREATE UNIQUE INDEX uq_user_identities_user_issuer
    ON user_identities (user_id, issuer, scope_tenant_id) NULLS NOT DISTINCT;

COMMENT ON TABLE user_identities IS
    'Federated identities (issuer + subject) bound to a global user account. Logins look the account up by this pair first; email is used only for first-time matching.';
COMMENT ON COLUMN user_identities.scope_tenant_id IS
    'NULL: only the issuer can assert the identity (OIDC id_token, social login). Set: a SAML identity, trusted only inside this organization.';

-- Move the single binding held on users.
INSERT INTO user_identities (user_id, issuer, subject, created_at)
SELECT id, federated_issuer, federated_subject, updated_at
FROM users
WHERE federated_issuer IS NOT NULL AND federated_issuer <> ''
  AND federated_subject IS NOT NULL AND federated_subject <> ''
  AND erased_at IS NULL
ON CONFLICT DO NOTHING;

ALTER TABLE users DROP COLUMN federated_issuer, DROP COLUMN federated_subject;
