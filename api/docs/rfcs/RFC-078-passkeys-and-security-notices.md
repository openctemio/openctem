# RFC-078: Passkeys and account security notices

| | |
|---|---|
| Status | Partially implemented: the platform console part (§7, 2026-10-16); the user-account phases P1 and P3 are Proposed |
| Scope | api (`pkg/domain/passkey`, `internal/app/auth` second factor, step-up and admin console step, known-device tracking, security notices, two migrations), web (account security page, sign-in second step, step-up dialog, admin console step) |
| Related | RFC-022 (platform admin console), RFC-024 (user two-factor authentication), RFC-009 (enterprise SSO), [step-up-reauth.md](../architecture/step-up-reauth.md), [user-two-factor-authentication.md](../architecture/user-two-factor-authentication.md) |

## 1. Summary

Users can register **passkeys** (WebAuthn credentials) on their account and
use them as a phishing-resistant second factor at sign-in, for step-up, and
for the platform-admin console. Later, an account that opts in can sign in
with a passkey alone. Every change to an account's factors, and every sign-in
from a device the account has not used recently, is emailed to the user and
audited.

Phases:

1. **P1:** passkeys as a second factor (next to TOTP) and as a step-up proof;
   notices for a new-device sign-in, 2FA enabled, passkey added and removed,
   and API key created.
2. **P2:** the admin console step accepts the user's own passkey or TOTP.
   The console's separate TOTP store (`admin_credentials`) is removed.
3. **P3:** passwordless sign-in with a discoverable passkey (conditional UI
   on the email field).

## 2. Motivation

- TOTP codes can be phished in real time: a proxy page relays the password
  and the code. A passkey is bound to our origin by the browser, so a
  look-alike domain cannot use it.
- A platform administrator holds two TOTP enrollments today: the account's
  own and the console's. That means two factor stores, two recovery stories
  and two code paths for one person.
- Users get no email when someone signs in from a new device or turns on 2FA
  for them. Those are the two notices that catch an account takeover early.

## 3. Design

### 3.1 Credential model

Table `user_passkeys`:

| Column | Notes |
|---|---|
| `id` | uuid, primary key |
| `user_id` | the owning account (user-level, like TOTP; no tenant column) |
| `credential_id` | bytea, unique |
| `public_key` | bytea (COSE) |
| `sign_count` | bigint; a counter that goes backwards on a non-synced credential refuses the assertion and is audited |
| `aaguid` | uuid, used for display only (no attestation policy) |
| `transports` | text[] |
| `backup_eligible`, `backup_state` | the flags from the authenticator data |
| `name` | user-given, ≤ 64 characters |
| `created_at`, `last_used_at` | timestamps |

Each account can hold at most 10 passkeys. A passkey counts as an enrolled
second factor wherever "2FA enabled" is checked today (organization 2FA
policy, owner 2FA, `MFARequiredForAdmins`).

The server uses the `go-webauthn/webauthn` library (Apache-2.0):

- relying-party ID: `WEBAUTHN_RP_ID`, default the host of `APP_BASE_URL`;
- origins: `WEBAUTHN_ORIGINS`, default `APP_BASE_URL`;
- `userVerification: required`;
- `attestation: none`;
- `residentKey: preferred` in P1 and `required` for new registrations in P3.

The browser side uses the native WebAuthn API with the JSON helpers,
`PublicKeyCredential.parseCreationOptionsFromJSON` where available, and a
small vendored fallback.

Challenges are single use with a 5-minute TTL. They are stored in Redis, keyed
by a random id and bound to the user id, and also to the session id when the
user is already signed in. Ceremony state never goes into a JWT.

### 3.2 Flows

- **Register (signed in):**
  `POST /users/me/passkeys/options` → `navigator.credentials.create` →
  `POST /users/me/passkeys`.
  Registering requires a step-up within the last 10 minutes (a password,
  TOTP or existing passkey proof), like the other factor changes.
- **Sign-in second step:** the password sign-in's `mfa_required` answer lists
  the available methods (`passkey`, `totp`, `recovery_code`):
  - `POST /auth/mfa/passkey/options` (with the challenge token) →
    `navigator.credentials.get` → `POST /auth/mfa/passkey/verify`;
  - the existing per-challenge attempt cap and account throttling apply.
- **Step-up:** `POST /auth/step-up` also accepts a passkey assertion. An
  assertion with user verification satisfies "fresh" step-up.
- **Admin console (P2):** `/admin/auth/session` asks for the user's own
  passkey or TOTP. Every platform administrator must enroll a user-level
  factor before P2 ships:
  - `bootstrap-admin` and the console refuse an admin without one;
  - a one-time migration notice lists the administrators who have none.
  
  After P2, `admin_credentials` is dropped.
- **Passwordless (P3):** the sign-in page calls `navigator.credentials.get`
  with `mediation: "conditional"` on the email field
  (`autocomplete="username webauthn"`). A verified discoverable assertion
  completes the sign-in without the password or a second step.
  Organization policies still apply at token exchange:
  - SSO enforcement refuses a passkey session for an enforcing organization,
    except the owner and named exceptions, as today;
  - a passkey session satisfies a 2FA requirement.
- **Remove:** `DELETE /users/me/passkeys/{id}` requires step-up. Removing the
  last factor is refused while an organization the user belongs to requires
  2FA.
- **Admin-assisted reset:** the existing tenant-admin "reset 2FA" also removes
  passkeys.

Federated accounts (SSO, SAML, social) do not register passkeys: their
identity provider owns the factors. This is the same rule as TOTP.

### 3.3 New-device detection and notices

Table `user_known_devices`:

| Column | Notes |
|---|---|
| `user_id` | the account |
| `device_hash` | hash (HMAC with the token pepper) of browser family + OS family + the IP's /24 (IPv4) or /48 (IPv6) |
| `first_seen_at`, `last_seen_at` | timestamps |

Primary key: (`user_id`, `device_hash`).

Raw user agents and addresses are not stored here; the session row already
holds them for the sessions list. Rows unused for 90 days are deleted by the
existing session cleanup job.

On every completed sign-in (password, second factor, SSO, SAML, social,
passkey):

- an unknown `device_hash` → audit `auth.new_device` and a "New sign-in to
  your account" email with time, browser, OS, approximate network and a link
  to Sessions. The email is sent after the response;
- a user's first-ever sign-in records the device without an email.

Security notices, all sent after the change commits, failures only logged:

| Event | Email | Opt-out |
|---|---|---|
| sign-in from a new device | yes | yes (Preferences) |
| 2FA enabled (TOTP or first passkey) | yes | no |
| passkey added / removed | yes | no |
| 2FA disabled, recovery code used, password changed or reset | yes (exists) | no |
| API key created on the user's behalf | yes | no |

### 3.4 Audit

New actions: `auth.passkey_registered`, `auth.passkey_removed`,
`auth.passkey_used`, `auth.passkey_counter_regressed`, `auth.new_device`.
They are user-level events like the other `auth.*` factor events. An SSO sign-in
also writes the issuing organization's id.

## 4. Threat model

| Threat | Mitigation |
|---|---|
| Real-time phishing proxy relays the password and second factor | a passkey assertion is origin-bound; the proxy's origin fails RP ID / origin checks |
| Stolen session registers an attacker passkey for persistence | registration needs a fresh step-up, and the user is emailed at once (no opt-out) |
| Cloned non-synced authenticator | sign-count regression refuses the assertion and is audited; synced passkeys report 0 and are not counter-checked |
| Challenge replay | single-use Redis challenge bound to the user and session, 5-minute TTL |
| Account enumeration through passwordless | conditional UI asks the authenticator, not the server; the options endpoint for discoverable credentials returns the same answer for every request (no allowCredentials list) |
| Lost device locks the user out | TOTP and recovery codes stay; at least one other factor or recovery codes are suggested on the first passkey; admin-assisted reset exists |
| Admin console downgrade during P2 | the console accepts only user-level passkey or TOTP after the cut-over; no fallback to the old store |
| New-device emails used for mail bombing | sent only after a successful sign-in, at most one per device hash per day |
| Privacy | known-device rows hold only keyed hashes; no third-party geolocation |

Tenant isolation: passkeys and known devices belong to the user and carry no
organization data. The organization 2FA policy reads only "has an enrolled
factor". No route takes a tenant id.

## 5. Not built

- No attestation or authenticator allow-lists (enterprise demand only).
- No SMS or email one-time codes.
- No hardware-key-only organization policy until a customer asks. The data
  (`aaguid`, `backup_state`) is kept so it can be added without a migration.
- No passkey management for federated users.

## 6. Migration and compatibility

- Two additive migrations: `user_passkeys`, `user_known_devices`.
- P2 drops `admin_credentials` after every platform administrator has
  enrolled a user-level factor. The drop is a contract migration.
- No change for users without passkeys. TOTP stays a first-class factor.

## 7. Amendment: the platform console (2026-10-16)

The console moves to its own origin (`OPENCTEM_ADMIN_SITE`, the console's own
host or port). Its WebAuthn relying party is that origin, so console security
keys cannot be the user-level passkeys of §3, which are bound to the tenant
site. This amendment replaces P2 for the console.

### 7.1 Decisions

| ID | Decision | Reason |
|---|---|---|
| W1 | Relying party = the console origin, `ADMIN_PUBLIC_URL` (default the origin of `APP_URL`). The RP ID is its host; it is the only accepted origin | the browser binds the assertion to the origin: a relay on another domain, or a script on the tenant site (same host in port mode, other origin), cannot produce an accepted assertion |
| W2 | Console keys live in `admin_webauthn_credentials` (public key, counter, AAGUID, transports, UV/BE/BS flags, name), at most 10 per administrator | separate RP ID from the tenant site; no shared store is possible |
| W3 | `userVerification: required`, `residentKey: preferred`, `attestation: none`, ES256/EdDSA/RS256 as offered by the library | a key alone is not enough (PIN or biometric); no attestation keeps synced passkeys and every FIDO2 key usable, and needs no metadata service |
| W4 | Synced passkeys are allowed; the response shows "synced" (backup state). The AAGUID is stored, so an allow-list or a "device-bound only" option can be added without a migration | most administrators have a platform passkey; the stricter options are an owner decision (§7.5) |
| W5 | A counter that does not move forward refuses the assertion and is audited (`console.webauthn_counter_regressed`); 0 → 0 passes (synced passkeys) | cloned non-synced authenticators |
| W6 | Ceremony state is stored per console session and purpose (`admin_webauthn_ceremonies`), taken (deleted) by the finishing request, 5-minute TTL | a challenge is accepted once, only by the session that asked for it; no Redis dependency |
| W7 | Ten one-time recovery codes (60 bits each, SHA-256 at rest), shown once, regenerated with step-up; a recovery code completes a sign-in, never a step-up | the lost-key path that needs no other administrator |
| W8 | Step-up with a key opens the session's five-minute step-up window; the action is retried without a code | one mechanism for route-level and handler-level step-ups |
| W9 | Policy "require security keys" (platform setting `console_mfa_policy`, super admin + step-up), off by default | the off → on path below never locks anyone out |
| W10 | TOTP stays (fallback, and the only factor of an administrator without keys). `admin_credentials` is not dropped yet | dropping it is a contract step once every administrator holds keys |

### 7.2 "Require security keys": the off → on path

1. Each administrator registers keys and recovery codes while the policy is
   off (registration takes a step-up with TOTP or an existing key).
2. A super admin turns the policy on. The API refuses unless the console has
   a relying party and the actor has **at least two keys and unused recovery
   codes**, so the person turning it on can always sign in.
3. Under the policy:
   - an administrator holding a key must use it: TOTP is refused at sign-in
     and step-up (403 `WEBAUTHN_REQUIRED`); recovery codes still work;
   - a platform-IdP sign-in whose MFA is trusted still asks for the key;
   - an administrator with fewer than two keys or no recovery codes can still
     sign in (TOTP while they hold no key), but the session reaches only the
     enrollment routes (403 `FACTOR_ENROLLMENT_REQUIRED`) until they comply;
   - the last two keys cannot be removed (register a replacement first);
   - break-glass administrators keep TOTP (they exist for the day the normal
     path fails).
4. A lost key: sign in with the other key or a recovery code; a super admin's
   reset-credentials removes every factor so the administrator enrolls again.
5. Turning the policy off needs no compliance check.

### 7.3 API

| Route | Who | Notes |
|---|---|---|
| `POST /api/v1/admin/auth/webauthn/session/options`, `POST …/webauthn/session` | pending sign-in | login rate limit; a refused assertion counts toward the lockout |
| `POST /api/v1/admin/auth/recovery` | pending sign-in | as above |
| `GET /api/v1/admin/auth/factors` | own | keys (no key material), codes left, policy, `enrollment_required` |
| `POST …/webauthn/credentials/options`, `POST …/webauthn/credentials` | own | options take the route-level step-up; the finish call completes that ceremony |
| `PATCH`, `DELETE …/webauthn/credentials/{id}` | own | delete takes the step-up and keeps the floor |
| `POST /api/v1/admin/auth/recovery-codes` | own | step-up; `Cache-Control: no-store` |
| `POST …/step-up/webauthn/options`, `POST …/step-up/webauthn` | own session | opens the step-up window |
| `GET`, `PUT /api/v1/admin/settings/console-mfa` | any / super admin + step-up | version compare-and-swap |

The sign-in answer (`/auth/session`) adds `methods`, in order of preference.
Audit actions: `console.webauthn_registered`, `console.webauthn_removed`,
`console.webauthn_renamed`, `console.webauthn_failed`,
`console.webauthn_counter_regressed`, `console.recovery_codes_generated`,
`console.recovery_code_used`, `console.recovery_code_failed`,
`console.mfa_policy_changed`, and `console.step_up` with the note `webauthn`.

### 7.4 Threat model (console)

| Threat | Control |
|---|---|
| Real-time phishing proxy relays the password and TOTP | under the policy, an administrator with a key cannot use TOTP; the key's assertion is bound to the console origin |
| Script on the tenant site asks for a console assertion (port mode shares the host, so the RP ID) | the origin in the client data is the tenant origin: refused (only the console origin is accepted) |
| Stolen console session adds an attacker key | registration needs a fresh step-up (TOTP or an existing key) and is audited at high severity; ceremonies are bound to the session |
| Stolen session removes keys or replaces recovery codes | both take a step-up; the floor keeps two keys under the policy |
| Challenge replay | single-use ceremony per session and purpose, 5-minute TTL, deleted on use |
| Cloned non-synced key | counter regression refused and audited |
| Another administrator's key | the assertion must match one of the signing-in administrator's own credentials and user handle |
| Turning the policy on locks administrators out | actor must comply; others are held on enrollment, not refused; break-glass keeps TOTP; reset-credentials remains |
| Grace period abused (TOTP of an administrator without keys is phished, then a key is registered) | the window lasts only until each administrator enrolls; registration is audited; super admins see compliance in Security > My security keys; enrol before turning the policy on |
| Recovery code guessing | 60-bit codes, behind the password step, the login rate limit and the lockout |
| Changing `ADMIN_PUBLIC_URL` | registered keys stop working (different RP ID); administrators sign in with TOTP or a recovery code and register again; documented in the variable |

Tenant isolation: none of these tables or routes carry tenant data; every
query is keyed on the calling administrator.

### 7.5 Open owner decisions

- O1: allow synced passkeys under the policy (default yes) or require
  device-bound keys (backup-eligible = false).
- O2: an AAGUID allow-list for the console (default none).
- O3: break-glass administrators keep TOTP under the policy (default yes).
