### Fixed: invitation to first open no longer dead-ends on two-factor authentication
- Accepting an invitation to an organization that needs a second factor now says "You have joined {org}" and sets up two-factor authentication in place, then opens the organization. It no longer reports "Cannot accept the invitation" after the membership exists.
- The sign-in offers two-factor setup whenever any organization would refuse the session: 2FA by role, `allowed_with_mfa` for personal addresses, and privileged outside members. It used to offer it only for the first, so those people looped on "sign in again". The setup screen names the organization that requires it.
- "2FA required for administrators" now follows effective privilege (an administrator or other privileged RBAC role held by a base-role member counts), at the token mint and at sign-in.
- A token refresh refused for 2FA keeps the person signed in and opens a full-page setup screen instead of sending them to the sign-in page. The refused refresh no longer spends the refresh token.
- The role summary on the invitation card is written as sentences instead of a dotted list.

### Added: `POST /api/v1/auth/mfa/enroll/session`
- Issues the second-factor challenge for a signed-in session that an organization holds back (refresh-token cookie or body, same CSRF rules as `accept-with-refresh`). Not available to sessions started through an identity provider.
- Starting two-factor enrollment from a session alone needs a sign-in within the last 15 minutes; an older session gets 403 `REAUTH_REQUIRED` and is sent to the password sign-in. A stolen refresh token can no longer bind an authenticator to an account without a second factor.
