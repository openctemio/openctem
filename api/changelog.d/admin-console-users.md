### Added: find any account and help it sign in again from the platform admin console

- Customers > Users searches accounts across organizations by email, name or id (`GET /api/v1/admin/platform-users?q=`, 3+ characters). An account page shows its organizations, linked identities, active sessions and sign-in state (`GET /api/v1/admin/platform-users/{userId}`, audited).
- Operations admins and up can sign an account out everywhere, unlock it, email it a password reset link or a new verification link (`POST .../{userId}/revoke-sessions|unlock|password-reset|resend-verification`). Each needs a reason, is audited and rate-limited; links go only to the account's mailbox. Platform administrator and erased accounts are refused.
- Ctrl/Cmd+K finds accounts as well as organizations.
