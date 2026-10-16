# RFC-078: Passkeys and account security notices

| | |
|---|---|
| Status | Proposed (2026-10-11) |
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
- **Admin console (P2):** `/admin/auth/login` asks for the user's own
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
