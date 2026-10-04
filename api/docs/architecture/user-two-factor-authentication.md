# User two-factor authentication, sessions and My account

Design rationale: [RFC-024](../rfcs/RFC-024-user-two-factor-authentication.md).
Status: **shipped** for local-password users of organizations. The platform admin
console has its own TOTP (RFC-022) and does not use this.

## Login flow

```
POST /api/v1/auth/login {email,password}
  ├─ password wrong ............................ 401 (counts toward lockout)
  ├─ 2FA enabled ............................... 200 {mfa_required, mfa_token, mfa_purpose:"verify", expires_in}
  ├─ an org requires 2FA, user not enrolled .... 200 {mfa_required, mfa_token, mfa_purpose:"enroll", expires_in}
  └─ otherwise ................................. 200 login response + refresh_token cookie (unchanged)

POST /api/v1/auth/mfa/verify          {mfa_token, code | recovery_code} → login response + cookie
POST /api/v1/auth/mfa/enroll/start    {mfa_token}                       → {secret, otpauth_uri}
POST /api/v1/auth/mfa/enroll/confirm  {mfa_token, code}                 → login response + recovery_codes + cookie
```

After a successful second step the response is the same as a plain password login, so
the client continues with `/auth/token` (tenant selection) as before.

The `mfa_token`:
- is 32 random bytes, hex-encoded, and is not a JWT. `UnifiedAuth` and the refresh-token
  validator both reject it (401).
- is stored only as SHA-256 in `user_mfa_challenges`.
- expires after 5 minutes, works once, and is burned after 5 wrong codes.
- is purpose-bound: a `verify` token cannot enroll, and an `enroll` token cannot verify.

Wrong codes increment `users.failed_login_attempts`. After `AUTH_MAX_LOGIN_ATTEMPTS`
the account is locked for `AUTH_LOCKOUT_DURATION`, the same lockout as wrong
passwords. The counter is reset only after the second step succeeds. The
`/auth/mfa/*` routes have their own rate-limit buckets (10/min per challenge,
30/min per IP), counted in Redis so every API replica shares them (see
[Authentication rate limits](../redis-production-guide.md#authentication-rate-limits)).

## Self-service API (`/api/v1/users/me/...`)

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/2fa` | | `{supported, enabled, enabled_at, recovery_codes_remaining, required_by_organization}` |
| POST | `/2fa/setup` | | New pending secret `{secret, otpauth_uri}`. 409 if already enabled. Changes nothing until enable. |
| POST | `/2fa/enable` | `{code}` | Confirms the pending secret, returns 10 recovery codes, **signs out every other session**. |
| POST | `/2fa/disable` | `{password, code}` | `code` = TOTP or unused recovery code. E-mails the user. |
| POST | `/2fa/recovery-codes` | `{code}` | TOTP only. Replaces all codes, returns the new ones. |
| POST | `/change-password` | `{current_password, new_password}` | Keeps the current session, revokes the others immediately, e-mails the user. |
| GET | `/sessions` | | `{sessions:[{id, ip_address, user_agent, created_at, last_activity_at, is_current}]}` |
| DELETE | `/sessions/{id}` | | Revoke one session (immediate). |
| DELETE | `/sessions` | | Revoke all except the current one (immediate). |

The mutating 2FA routes carry the CSRF check and an auth rate limiter (`setup`/`enable`:
5/min, `disable`/`recovery-codes`: 3/min per IP). Responses that contain secrets or
codes are sent with `Cache-Control: no-store`. Federated accounts get
`supported:false`, and the mutating calls return 400.

## Organization policy ("Require MFA")

The setting is `tenant.settings.security.mfa_required`. Only the owner can change it,
through `PATCH /tenants/{t}/settings/security` (Settings → Organization → Security).

- Login: a member of any organization that requires 2FA, who has not enrolled, gets an
  enrollment challenge. They cannot get a session until they enroll.
- Token mint (`/auth/token`, `/auth/refresh`): a password session of an unenrolled user
  gets `403 {code:"MFA_ENROLLMENT_REQUIRED"}` for a tenant that requires 2FA. The UI
  then signs the user out and back in, which leads to enrollment. A policy turned on
  mid-session therefore takes effect within one access-token lifetime (15 min default).
- A session issued by **this organization's own** SAML/OIDC provider passes: the
  organization chose that IdP, and it owns the second factor.
- Any other federated session — social OAuth (GitHub/Google/personal Microsoft),
  another organization's IdP, or an SSO session created before migration `000269`
  recorded the issuing organization — never went through our second step, so it
  gets `403 {code:"MFA_ENROLLMENT_REQUIRED"}` for an organization that requires
  2FA, enrolled or not. The UI signs the user out; they sign in again with
  password and 2FA, or through that organization's IdP. Users and sessions are
  global, so without this a sign-in through organization B's IdP would get into
  organization A without A's 2FA. See `Session.FederatedFor` in
  [sso-authentication.md](sso-authentication.md#how-a-sessions-login-method-is-recorded).
- Owners and admins see each member's status in the members list
  (`GET /tenants/{t}/members?include=user` → `mfa_status`: `enabled`, `disabled` or
  `idp`). Other roles do not get the field.

## Immediate session revocation

```
revoke (logout | DELETE /users/me/sessions[/{id}] | password change/reset | enable 2FA | suspension)
  → sessions.status = revoked, refresh tokens revoked              (Postgres, as before)
  → SET blacklist:session:<session_id> EX (access TTL + 1m)        (Redis, new)

every authenticated request
  → UnifiedAuth validates the JWT
  → EXISTS blacklist:session:<claims.session_id> ? 401 "Session has been revoked"
```

- Without Redis the check is off and access tokens expire naturally.
- A Redis error fails open (logged).

## Storage (migration 000228)

| Table | What | Protection |
|---|---|---|
| `user_mfa` | active + pending secret, `enabled`, `enabled_at`, `last_used_step` | secret AES-256-GCM (`APP_ENCRYPTION_KEY`); `last_used_step` updated by compare-and-set (replay) |
| `user_mfa_recovery_codes` | 10 codes, `used_at` | bcrypt cost 10, consumed with `WHERE used_at IS NULL` |
| `user_mfa_challenges` | login challenges | SHA-256 token hash, `expires_at`, `attempts`, `consumed_at`; expired rows deleted by the hourly session cleanup |

All three tables cascade on user delete. They are per-user, not tenant data.

Without `APP_ENCRYPTION_KEY` (development only) the secret is stored as plaintext, as
integration credentials are.

## Audit and notifications

| Event | Audit action | E-mail (system SMTP) |
|---|---|---|
| 2FA turned on (self-service or forced enrollment) | `auth.mfa_enabled` (metadata `via`) | |
| 2FA turned off | `auth.mfa_disabled` | yes |
| 2FA reset by an organization owner/admin | `auth.mfa_reset` (high; actor, target user, metadata `membership_id`, `target_role`; in the caller's organization) | yes (same "turned off" notice) |
| Wrong second factor at login | `auth.mfa_failed` | |
| Recovery code used to sign in | `auth.mfa_recovery_code_used` (metadata `recovery_codes_remaining`) | yes |
| Recovery codes regenerated | `auth.mfa_recovery_codes_regenerated` | |
| Session signed out from My account | `auth.session_revoked` | |
| Password changed | `auth.password_changed` | yes (existing template) |

## Recovery

A user who lost their authenticator signs in with a recovery code, then disables and
re-enables 2FA, or regenerates codes after setting up a new device.

If the recovery codes are also lost, an owner or administrator of their organization
resets it: **Settings > Members**, row menu **Reset 2FA**
(`POST /api/v1/tenants/{tenant}/members/{membershipId}/reset-2fa`,
`AuthService.ResetMemberMFA`). The reset deletes the factor and the recovery codes,
revokes every session of the user (with immediate access-token revocation), writes
`auth.mfa_reset` and e-mails the user. If the organization requires 2FA, the user's next
login forces enrollment again.

The factor belongs to the user account, not to one organization, so the rules are:

- the target must be a member of the caller's organization (404 otherwise);
- the caller must be an active owner or administrator there (route `RequireTeamAdmin`,
  re-checked live in the service);
- nobody resets their own factor here: that is the self-service disable, which needs the
  password and a code, so a hijacked admin session cannot strip its own second factor;
- an owner or administrator target needs an owner caller (the peer-administrator rule);
- **the same authority is required in every other organization the target belongs to**,
  active or suspended. An administrator of organization A cannot weaken the account of
  someone who is also a member, administrator or owner of organization B unless they hold
  the same authority in B; otherwise 403 tells them to ask an administrator there.

An operator can still delete the row directly as a last resort:
`DELETE FROM user_mfa WHERE user_id = '<uuid>';` (recovery codes cascade).

## Key files

- `pkg/totp/totp.go`: RFC 6238 implementation (shared with the admin console)
- `pkg/domain/mfa/mfa.go`: entities and repository interface
- `internal/app/auth/mfa.go`: login integration, self-service operations, policy gate, revocation helper
- `internal/app/auth/service.go`: `Login` → `loginMFAChallenge` → `completeLogin`; `enforceMFAPolicy` in `ExchangeToken` / `RefreshToken`
- `internal/infra/postgres/user_mfa_repository.go`
- `internal/infra/redis/session_revocation.go`; `internal/infra/http/middleware/unified_auth.go` (`RevokedSessions`)
- `internal/infra/http/handler/local_auth_mfa_handler.go`; routes in `internal/infra/http/routes/auth.go`
- Tests: `tests/unit/auth_mfa_test.go`, `tests/unit/auth_mfa_handler_test.go`
- UI: `src/app/(dashboard)/account/security/page.tsx`, `src/features/account/`, `src/features/auth/components/mfa-step.tsx`
