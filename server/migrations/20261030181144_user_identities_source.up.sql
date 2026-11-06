-- Which sign-in path bound a federated identity. An organization's Entra ID
-- or Google Workspace single sign-on and the social Microsoft or Google button
-- verify the same issuer and subject, so the key alone does not tell them
-- apart:
--   social  bound by a social sign-in or an explicit link; the person may
--           unlink it from Account > Security;
--   sso     bound or used by an organization's single sign-on; managed by the
--           organization, never unlinked by the person, and a social sign-in
--           through it never changes the account.
-- The organization's sign-on marks an identity sso on every use, so the
-- default only covers a rolling deploy's old pods.
ALTER TABLE user_identities
    ADD COLUMN source text NOT NULL DEFAULT 'social'
        CONSTRAINT chk_user_identities_source CHECK (source IN ('social', 'sso'));

COMMENT ON COLUMN user_identities.source IS
    'social: bound by social sign-in or an explicit link (the person may unlink it). sso: bound or used by an organization''s single sign-on (managed by the organization).';

-- Existing rows. Over-marking only keeps an identity from being unlinked by
-- the person, so every doubtful row is sso.
-- SAML (organization-scoped) and any issuer other than the social providers.
UPDATE user_identities
SET source = 'sso'
WHERE scope_tenant_id IS NOT NULL
   OR (issuer NOT IN ('https://accounts.google.com', 'https://github.com')
       AND issuer NOT LIKE 'https://login.microsoftonline.com/%');

-- Microsoft: the account belongs to an organization with Entra ID sign-on for
-- this directory (the issuer names the directory id; a directory named by a
-- domain cannot be matched, so it counts too).
UPDATE user_identities ui
SET source = 'sso'
WHERE ui.source = 'social'
  AND ui.issuer LIKE 'https://login.microsoftonline.com/%'
  AND EXISTS (
      SELECT 1
      FROM tenant_members tm
      JOIN tenant_identity_providers tip ON tip.tenant_id = tm.tenant_id
      WHERE tm.user_id = ui.user_id
        AND tip.provider = 'entra_id'
        AND (COALESCE(tip.tenant_identifier, '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
             OR position(lower(tip.tenant_identifier) IN lower(ui.issuer)) > 0));

-- Google: the account belongs to an organization with Google Workspace sign-on.
UPDATE user_identities ui
SET source = 'sso'
WHERE ui.source = 'social'
  AND ui.issuer = 'https://accounts.google.com'
  AND EXISTS (
      SELECT 1
      FROM tenant_members tm
      JOIN tenant_identity_providers tip ON tip.tenant_id = tm.tenant_id
      WHERE tm.user_id = ui.user_id
        AND tip.provider = 'google_workspace');
