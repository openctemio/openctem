### Added: the account's memberships say what each organization needs, and a member can leave one it cannot open

- `GET /users/me/tenants` gives each organization an `admission`: `open`, or the code its token
  request would refuse this session with (`MFA_ENROLLMENT_REQUIRED`, `SSO_REQUIRED`,
  `OWN_SIGN_IN_REQUIRED`, `MFA_IDP_EVIDENCE_REQUIRED`, `EMAIL_NOT_VERIFIED`,
  `ORGANIZATION_SUSPENDED`), from the same rules as the token request, so the account space shows
  the one next step.
- `POST /api/v1/me/memberships/{tenantId}/leave` (account route, step-up, audited) leaves an
  organization from the account space, including one that does not admit the session.
- Docs: server/docs/architecture/tenantless-account-space.md
