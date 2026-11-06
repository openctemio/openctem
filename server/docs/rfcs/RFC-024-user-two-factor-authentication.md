# RFC-024: Two-factor authentication and account security for organization users

| | |
|---|---|
| Status | Implemented |
| Scope | Local-password users of organizations. Not the platform admin console (RFC-022), not federated users. |
| Architecture doc | [`docs/architecture/user-two-factor-authentication.md`](../architecture/user-two-factor-authentication.md) |

## Problem

- The UI had a "Two-Factor Authentication" card calling `/api/v1/users/me/2fa`, with no
  backend behind it. The button was disabled ("Coming soon").
- The tenant setting `security.mfa_required` ("Require MFA") could be saved but nothing
  enforced it.
- Signing a session out (per-device sign-out, "sign out all others", password change)
  revoked the session row and its refresh tokens, but its access token kept working
  until it expired (up to 15 minutes).
- Changing the password signed out every session, including the one making the change.

## Decisions

1. **TOTP (RFC 6238) using the in-house `pkg/totp`** that the admin console already uses.
   No new dependency. SHA-1, 6 digits, 30 s, ±1 step.
2. **Second-factor state lives in its own tables** (`user_mfa`,
   `user_mfa_recovery_codes`, `user_mfa_challenges`, migration 000228). It stays out of
   `users`, the same split as `admin_credentials`.
3. **The secret is encrypted with the application AES-256-GCM key** (`APP_ENCRYPTION_KEY`,
   the same `crypto.Encryptor` used for integration credentials). Recovery codes are
   bcrypt hashes (cost 10). Login challenges are SHA-256 hashes.
4. **The login challenge is not a session.** A password login that needs a second step
   returns an opaque 256-bit random token (not a JWT). It is valid for 5 minutes and
   single use, and it is burned after 5 wrong codes. Only the `/auth/mfa/*` steps accept
   it. No session row, refresh token or cookie exists until the code is verified.
5. **Replay protection:** the newest accepted time step is stored per user and updated
   with a compare-and-set (`UPDATE … WHERE last_used_step < $step`). A code from the
   same or an earlier step is rejected, including two concurrent requests that carry
   the same code.
6. **Lockout reuses the account lockout.** Wrong codes call `RecordFailedLogin`
   (`AUTH_MAX_LOGIN_ATTEMPTS` / `AUTH_LOCKOUT_DURATION`). While a second step is pending,
   a correct password does not reset the counter, so alternating "right password, wrong
   code" still locks the account. The `/auth/mfa/*` steps use the login rate limiter
   (5 per minute per IP).
7. **Organization policy** reuses `tenant.Settings.Security.MFARequired`, which is
   owner-only through `PATCH /tenants/{t}/settings/security`. It is enforced in two places:
   - at login: a member of any organization that requires 2FA, who has not enrolled,
     gets an *enrollment* challenge. That challenge can only start and confirm enrollment;
     the session is issued after confirmation.
   - at token mint (`/auth/token`, `/auth/refresh`), next to the SSO-enforcement gate:
     a password session of an unenrolled user cannot mint a token for a tenant that
     requires 2FA (`403 MFA_ENROLLMENT_REQUIRED`). This is what keeps refresh from
     bypassing a policy that was turned on mid-session.
8. **Federated users are never prompted.** SSO/SAML/OAuth logins do not go through
   `Login`, and the token-mint gate skips federated sessions. Their identity provider
   owns the second factor. `/users/me/2fa` reports `supported: false` for them.
9. **Immediate revocation:** a revoked session's id is written to Redis (the existing
   `TokenStore` blacklist, prefix `session:`) with a TTL of the access-token lifetime
   plus 1 minute. `UnifiedAuth` rejects tokens of that session on the next request.
   The check runs on every authenticated route. A Redis lookup error fails open and is
   logged, so the token still expires on its own.
10. **Enabling 2FA signs out every other session.** A session opened with a stolen
    password before 2FA was turned on does not survive it.
11. **Password change keeps the current session** and revokes the others (it used to
    revoke all of them). Password reset still revokes all.
12. **Disabling 2FA needs the current password and a valid code** (TOTP or recovery
    code). **Regenerating recovery codes needs a TOTP code** (not a recovery code).
13. **Audit and e-mail.** New audit actions: `auth.mfa_enabled`, `auth.mfa_disabled`,
    `auth.mfa_failed`, `auth.mfa_recovery_code_used`,
    `auth.mfa_recovery_codes_regenerated`, `auth.session_revoked`,
    `auth.password_changed`. When system SMTP is configured, the user is e-mailed when
    2FA is disabled, when a recovery code is used, and when the password changes.

## Not done / out of scope

- WebAuthn / passkeys.
- An admin "reset this member's 2FA" action. Today a locked-out user uses a recovery
  code. A platform administrator can delete the user's `user_mfa` row; no UI does this.
- Personal API keys. API keys are organization-level (`/api/v1/api-keys`, permission
  gated). There is no per-user key feature to show on My account.
- A per-request 2FA-policy gate. Policy changes take effect at the next token refresh,
  at most one access-token lifetime later.
