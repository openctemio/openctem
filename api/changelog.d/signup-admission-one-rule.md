### Security: one admission rule for every sign-up path; no orphan accounts

- Register, the first Google/GitHub/Microsoft sign-in, OIDC/SAML just-in-time
  provisioning, create-first-team and `POST /tenants` all apply one rule
  (`signup.Admit`) against the console sign-up policy. In `admin_only`, an
  account is created only for a pending invitation or an organization's SSO;
  nothing else writes a row. With the old flags, `TENANT_CREATION_MODE=admin_only`
  plus `AUTH_ALLOW_REGISTRATION=true` let a social sign-in create an account
  that could never get an organization.
- A social sign-in whose verified email has a pending invitation may now create
  the account in `admin_only` too (before, it was refused).
- Every refusal answers 403 `SIGNUP_NOT_AVAILABLE`; the web shows one
  "Your organization isn't set up yet" page (`/not-set-up`, en/vi) whatever the
  reason. An existing account signs in as before.

### Removed: AUTH_ALLOW_REGISTRATION

- The sign-up policy (Console > System > Sign-up, seeded from
  `TENANT_CREATION_MODE`) decides who may register. `registration_enabled` on
  `/auth/providers` and `/auth/info` is true exactly in `self_service`.
- **Upgrade note:** remove `AUTH_ALLOW_REGISTRATION` from your environment
  (startup logs a warning while it is set and ignores it). If you ran
  `AUTH_ALLOW_REGISTRATION=true` for open sign-up, set the policy to
  `self_service` in the console. Accounts that belong to no organization and
  are not administrators (left by the old combination) can be listed with
  `SELECT id, email, created_at FROM users u WHERE NOT EXISTS (SELECT 1 FROM tenant_members m WHERE m.user_id = u.id) AND NOT EXISTS (SELECT 1 FROM admin_users a WHERE a.user_id = u.id);`
  they keep signing in and see the "not set up" guidance until invited.
