### Fixed: sign-in dead ends found by the sign-in scenario suite

- "2FA for administrators" (and the platform floor `admins`) no longer gates a plain member: administrator now means grants above the built-in member role (`permission.IsAboveMember`); the member role's own permissions never count.
- Accepting an invitation of a suspended organization is refused with 403 `ORGANIZATION_SUSPENDED` before anything changes (no membership, the invitation stays pending), and the session is kept: the invitation acceptance no longer spends the refresh token before its access token is minted.
- `/auth/token` has the same refresh-token rotation grace as `/auth/refresh`: two tabs opening two organizations at once, or a tab that missed a rotation by seconds, keep the session. A token re-presented after the grace, from a client whose User-Agent differs (the console now forwards the browser's on both calls; a User-Agent is not a secret, so this stops another kind of client, not a copy of it), or after its successor rotated still ends the session and is audited.
- A request refused per organization because single sign-on became required answers `SSO_REQUIRED` (was `FORBIDDEN`), and one refused for the identity provider's second-factor proof answers `MFA_IDP_EVIDENCE_REQUIRED`, as at token issuance.
- A token request refused because the organization does not accept personal accounts answers 403 `PERSONAL_ACCOUNTS_BLOCKED` (was a 500).
- Accepting an invitation sent to another address answers 403 `INVITATION_FOR_ANOTHER_ADDRESS`; the invitation page then says to sign in with that account. After a refusal only another sign-in can fix (the organization's identity provider required, another organization's provider, another address), the invitation page shows that one step instead of offering Accept or Open again.
- A session ended because its organization is suspended says so on the sign-in page instead of showing a bare form.
- Test builds only: the build tag `authtestseam` lets the sign-in test suites reach the social providers at a stand-in; release builds never carry it.
- Docs: server/docs/architecture/two-factor-floor.md, server/docs/architecture/session-refresh.md, server/docs/architecture/organization-suspension.md, server/docs/development/auth-scenarios.md
- A hand-out inside the rotation grace is audited (`auth.refresh_grace`, low severity).
- `/auth/refresh` checks the membership before whether the organization is suspended, so a session cannot learn whether an organization it is not in is suspended.
- The sign-in test seam is honoured only in a binary built with the `authtestseam` tag and with `APP_ENV` set to `test` or `e2e`. The release build script refuses build tags in `GOFLAGS` and fails a binary that carries the tag.
