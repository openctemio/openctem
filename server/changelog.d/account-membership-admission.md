### Added: the account's memberships say what each organization needs, and a member can leave one it cannot open

- `GET /users/me/tenants` gives each organization an `admission`: `open`, or the code its token
  request would refuse this session with (`MFA_ENROLLMENT_REQUIRED`, `SSO_REQUIRED`,
  `OWN_SIGN_IN_REQUIRED`, `MFA_IDP_EVIDENCE_REQUIRED`, `EMAIL_NOT_VERIFIED`,
  `ORGANIZATION_SUSPENDED`), from the same rules as the token request, so the account space shows
  the one next step. Each also carries `requires` (`two_factor`, `identity_provider`): what the
  organization asks of every sign-in of this member, shown before opening it.
- `POST /api/v1/me/memberships/{id}/leave` (account route, step-up, audited) leaves an
  organization from the account space, including one that does not admit the session.
- Listing the memberships (`GET /users/me/tenants`) no longer records an owner break-glass
  sign-in or notifies administrators: only a token that is minted does. The per-organization
  `admission` is computed for an account token only. Two owners leaving an organization at the
  same moment can no longer leave it without an owner (the owner rows are locked inside the
  offboarding transaction). A member removed from the organization in the tenant cookie is sent
  to the account space and only that cookie is cleared.
- Docs: server/docs/architecture/tenantless-account-space.md
