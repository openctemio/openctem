# RFC-022 — Platform administration console (Tenable-style system admin)

> Status: **Accepted** (2026-09-30) — Phase 1 implemented
> Scope: api + ui. Separates *application (platform) administration* from
> *organization (tenant) administration*, modeled on Tenable Security Center,
> where the system administrator has a different login and a different menu
> (Organizations, Users, Scanning, System) from organization users.

## Problem

1. **Identity-federation setup belonged to the wrong tier.** Every tenant admin
   could configure SAML, identity providers and verified domains for their own
   tenant. api#545 moved that behind a *platform admin* flag, but the flag is a
   stop-gap: it is an env allow-list (`PLATFORM_ADMIN_EMAILS`) stamped onto a
   normal tenant user, so the platform admin is still a tenant user, and SSO is
   still configured "for the tenant I am in", not per organization.
2. **The operator console has no human login.** `/api/v1/admin/*` (admin users,
   admin audit logs, target mappings) authenticates only with `X-Admin-API-Key`.
   That suits the CLI, not a person at a browser: no password, no MFA, no
   revocable session.
3. **No cross-tenant view.** A platform admin cannot list organizations, create
   or suspend one, or configure one's SSO without being a member of it.
4. **The tenant UI shell cannot host an admin.** The dashboard layout requires a
   tenant (TenantGate + `/me/bootstrap` + the tenant switcher); an identity with
   no tenant errors or is pushed to onboarding.

## Decisions

| # | Decision | Why |
|---|----------|-----|
| D1 | **Identity = `admin_users`**, separate from tenant `users`. | A compromised tenant account can never become platform admin; roles (`super_admin` > `ops_admin` > `readonly`), lockout and the admin audit log already exist. `PLATFORM_ADMIN_EMAILS` becomes transitional and is retired in Phase 3. |
| D2 | **Same backend.** Extend `/api/v1/admin/*`; no second service. | Admin operations (create org, assign bundles, configure SSO) need the same tenant/module/SSO services. A second service would duplicate logic or call back into the api. |
| D3 | **Human login = password + mandatory TOTP**, server-side sessions. API keys stay for CLI/automation. | Admin sessions must be revocable (server-side), short-lived, and MFA-protected. No password-only session exists. |
| D4 | **TOTP implemented in-house** (RFC 6238: HMAC-SHA1, 6 digits, 30 s, ±1 step), verified against the RFC test vectors. | No OTP library is in `go.mod`; ~50 lines is easier to audit than a new dependency on the admin auth path. Reusable later for tenant-user 2FA, which is also missing (the UI calls `/users/me/2fa`, which has no backend). |
| D5 | **Same Next.js app, separate shell** (own route group, layout, login, sidebar; shared `SidebarBrand`). | Tenable does the same: one application, a different menu per account type. Can be split into its own deployable later because the route group is independent. `/admin` + `/api/v1/admin` can be IP-restricted at the ingress. |
| D6 | **SCIM stays a tenant-admin feature** (api#546). | The tenant's own IT connects their IdP. |
| D7 | **Bundles become licensing only through a separate entitlement layer.** | Today a tenant admin's per-module "on" override beats the bundle baseline, and the module gate is fail-open, so locking bundle *subscription* alone would lock nothing. Entitlement (platform-set ceiling, fail-closed) ⊇ subscription (tenant) ⊇ toggles. OSS default: entitled to everything. |
| D8 | **Organization creation is a per-installation setting**, `TENANT_CREATION_MODE=self_service\|admin_only` (default `self_service`). | SaaS/trials need self-service; on-prem/enterprise wants admin-only (Tenable). The platform admin can always create organizations. |

## Design — Phase 1: console authentication (api)

**Schema** (migration `000225`). Credentials sit in their own table rather than
new `admin_users` columns, so secrets stay apart from the identity row and the
existing admin read paths never load them:

- `admin_credentials` (1:1 with `admin_users`): `password_hash` (bcrypt, cost
  12), `mfa_secret_encrypted` (AES-GCM via the application `Encryptor`),
  `mfa_enabled`, `mfa_last_step` (replay protection: a TOTP code is accepted only
  if its time step is newer than the last accepted one, enforced by a single
  conditional `UPDATE`), `password_changed_at`.
- `admin_sessions`: `id`, `admin_id` (FK, cascade), `token_hash` (SHA-256 of a
  32-byte random token; the token itself is never stored), `mfa_verified`,
  `created_at`, `expires_at`, `last_seen_at`, `ip`, `user_agent`.

**Flow** (`/api/v1/admin/auth`):

1. `POST /login {email, password}`: rate-limited per IP; reuses the existing
   `failed_login_count` / `locked_until` lockout. On success it creates a
   *pending* session (`mfa_verified=false`, 5-minute expiry) in an HttpOnly
   `admin_mfa` cookie and answers `mfa_required`, or `mfa_enrollment_required`
   with a freshly generated secret + `otpauth://` URI when MFA is not set up.
   Every failure (unknown email, inactive, locked, no password, wrong password)
   is the same generic 401, with timing equalized by a dummy bcrypt compare. A
   locked account is not password-checked at all, so lockout cannot confirm a
   guessed password.
2. `POST /mfa {code}`: verifies the TOTP (constant-time, ±1 step). On first
   enrollment this also enables MFA. The pending session is deleted and a new
   verified session is issued in the `admin_session` cookie (HttpOnly, Secure
   per `AUTH_COOKIE_SECURE`, `SameSite=Strict`, `Path=/api/v1/admin`), plus a
   readable `admin_csrf` cookie. It is separate from the tenant `csrf_token` so
   both shells can be open in one browser. Session lifetime: 8 h absolute,
   30 min idle. Wrong codes count toward the same lockout as wrong passwords.
3. `POST /logout`: deletes the session and clears the cookies.
4. `POST /password {current_password?, new_password}`: sets or changes the
   caller's own password. Callable with an API key (bootstrap path: the operator
   holds the key printed by `bootstrap-admin`) or a verified session (then the
   current password is required).

**Authentication middleware**: `AdminAuthMiddleware.Authenticate` accepts
either the API key (unchanged) or a verified, unexpired `admin_session`
cookie. Cookie-authenticated state-changing requests must pass the existing
double-submit CSRF check. Every existing `/admin/*` route and role guard then
works from a browser unchanged.

**Bootstrap**: `bootstrap-admin` creates the first `super_admin` with an API
key (unchanged); the operator sets a password with the key
(`POST /admin/auth/password`), then logs in to the console and enrolls TOTP.
A `super_admin` can reset another admin's password/MFA
(`POST /admin/users/{id}/reset-credentials`, audited).

## Later phases

- **Phase 2 (api) — Organizations.** `GET/POST /admin/tenants`, suspend/
  reactivate; per-organization SSO under `/admin/tenants/{id}/sso/*` (SAML,
  identity providers, verified domains, **SSO enforcement**, moved out of the
  tenant owner's `settings/security`); `TENANT_CREATION_MODE`; delete the dead
  `sso_enabled` / `sso_provider` / `sso_config_url` security fields (written,
  never read by the login path).
- **Phase 3 (ui) — console shell.** `/admin/login` + MFA, and a Tenable-style
  sidebar: Overview · Organizations · Users · Scanning (target mappings,
  platform tools) · System (Configuration, Diagnostics, Job queue, System logs,
  Keys). Replaces the transitional `(dashboard)/admin` pages; retires
  `PLATFORM_ADMIN_EMAILS` and the tenant-JWT SSO setup routes.
- **Phase 4 — Entitlements.** Platform-set bundle ceiling per organization,
  fail-closed, that per-module overrides cannot exceed.

## Security notes

- The admin session cookie is scoped to `/api/v1/admin`, so it is never sent to
  tenant routes, and the tenant JWT never authenticates admin routes.
- Server-side sessions: deactivating an admin or resetting credentials deletes
  all of that admin's sessions immediately.
- All login outcomes and credential changes are written to `admin_audit_logs`.
