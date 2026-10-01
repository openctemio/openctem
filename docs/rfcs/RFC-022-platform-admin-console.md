# RFC-022 — Platform administration console (Tenable-style system admin)

> Status: **Accepted** (2026-09-30) — Phases 1-3 implemented (api#547, api#548, ui#505).
> **Revision 2** (2026-09-30): the administrator is a user account signing in on
> the normal `/login` (see [Revision 2](#revision-2-administrators-are-user-accounts)).
> **Revision 3** (2026-10-01): administrators have no API keys (see
> [Revision 3](#revision-3-no-admin-api-keys)).
> Scope: api + ui. Separates *application (platform) administration* from
> *organization (tenant) administration*, modeled on Tenable Security Center,
> where the system administrator is an account with a system-level role and a
> different menu (Organizations, Users, Scanning, System) from organization users.

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
| D1 | **Identity = a `users` account linked to `admin_users`** (rev. 2; originally `admin_users` alone). The account belongs to no organization (enforced in the database); `admin_users` holds the role (`super_admin` > `ops_admin` > `readonly`), the second factor, lockout and the admin audit trail. | Tenable SC: one account table, one login page, the Administrator role is system-level and belongs to no organization. Keeping the account out of every organization is what separates the tiers, not a second account table. `PLATFORM_ADMIN_EMAILS` is removed. |
| D2 | **Same backend.** Extend `/api/v1/admin/*`; no second service. | Admin operations (create org, assign bundles, configure SSO) need the same tenant/module/SSO services. A second service would duplicate logic or call back into the api. |
| D3 | **Console = password sign-in on `/login` + mandatory TOTP**, server-side console sessions. SSO/SAML sign-ins cannot open it. No admin API keys (rev. 3). | Admin sessions must be revocable (server-side), short-lived, and MFA-protected. No organization's IdP may authenticate a platform administrator. |
| D4 | **TOTP implemented in-house** (RFC 6238: HMAC-SHA1, 6 digits, 30 s, ±1 step), verified against the RFC test vectors. | No OTP library is in `go.mod`; ~50 lines is easier to audit than a new dependency on the admin auth path. Reusable later for tenant-user 2FA, which is also missing (the UI calls `/users/me/2fa`, which has no backend). |
| D5 | **Same Next.js app, separate shell** (own route group, layout, login, sidebar; shared `SidebarBrand`). | Tenable does the same: one application, a different menu per account type. Can be split into its own deployable later because the route group is independent. `/admin` + `/api/v1/admin` can be IP-restricted at the ingress. |
| D6 | **SCIM stays a tenant-admin feature** (api#546). | The tenant's own IT connects their IdP. |
| D7 | **Bundles become licensing only through a separate entitlement layer.** | Today a tenant admin's per-module "on" override beats the bundle baseline, and the module gate is fail-open, so locking bundle *subscription* alone would lock nothing. Entitlement (platform-set ceiling, fail-closed) ⊇ subscription (tenant) ⊇ toggles. OSS default: entitled to everything. |
| D8 | **Organization creation is a per-installation setting**, `TENANT_CREATION_MODE=self_service\|admin_only` (default `self_service`). | SaaS/trials need self-service; on-prem/enterprise wants admin-only (Tenable). The platform admin can always create organizations. |

## Design — Phase 1: console authentication (api, as revised)

**Schema.** Migration `000225` added `admin_credentials` and `admin_sessions`;
`000226` (rev. 2) links administrators to accounts. The console password
columns (`admin_credentials.password_hash`, `password_changed_at`) are no longer
used and are dropped in a later release (expand-contract):

- `admin_users.user_id` (unique, FK `users`, cascade). Rows without it were
  API-key identities; migration 000227 deactivated them (rev. 3).
- A trigger on `tenant_members` rejects a membership for a linked account
  (SQLSTATE 23514, surfaced as 409 "platform administrators cannot be members of
  an organization"); linking an account that has memberships is refused.
- `admin_credentials` (1:1 with `admin_users`): `mfa_secret_encrypted` (AES-GCM
  via the application `Encryptor`), `mfa_enabled`, `mfa_last_step` (replay
  protection: a TOTP code is accepted only if its time step is newer than the
  last accepted one, enforced by a single conditional `UPDATE`).
- `admin_sessions`: `id`, `admin_id` (FK, cascade), `token_hash` (SHA-256 of a
  32-byte random token; the token itself is never stored), `mfa_verified`,
  `created_at`, `expires_at`, `last_seen_at`, `ip`, `user_agent`.

**Flow.** The administrator signs in on the normal `/login` (email + password,
the account's own lockout and password policy). Login and `GET /users/me` report
`platform_admin` / `is_platform_admin`, and the UI sends the administrator to
`/admin` instead of organization onboarding. Then, under `/api/v1/admin/auth`:

1. `POST /session`: reads the `/login` refresh-token cookie (validated, not
   rotated). Refused with 401 when not signed in, 403 when the account is not
   linked to an active, unlocked administrator, and 403 when the sign-in came
   from SSO, SAML or a social provider (audited). Otherwise it creates a
   *pending* session (`mfa_verified=false`, 5-minute expiry) in an HttpOnly
   `admin_mfa` cookie and answers `mfa_required`, or `mfa_enrollment_required`
   with a freshly generated secret + `otpauth://` URI when MFA is not set up.
2. `POST /mfa {code}`: verifies the TOTP (constant-time, ±1 step). On first
   enrollment this also enables MFA. The pending session is deleted and a new
   verified session is issued in the `admin_session` cookie (HttpOnly, Secure
   per `AUTH_COOKIE_SECURE`, `SameSite=Strict`, `Path=/api/v1/admin`), plus a
   readable `admin_csrf` cookie. It is separate from the tenant `csrf_token` so
   both shells can be open in one browser. Session lifetime: 8 h absolute,
   30 min idle. Wrong codes count toward the administrator's lockout.
3. `POST /logout`: deletes the console session and clears its cookies (the UI
   also signs out of `/login`).

**Authentication middleware**: `AdminAuthMiddleware.Authenticate` accepts
only a verified, unexpired `admin_session` cookie (rev. 3 removed admin API
keys). The `/login` session alone authenticates nothing under `/api/v1/admin`.
Cookie-authenticated state-changing requests must pass the double-submit CSRF
check. Every `/admin/*` route and role guard works from a browser unchanged.

**Provisioning**: `POST /api/v1/admin/administrators {email, name, role}`
(super admin, audited) links the account with that email, or creates a local
account and returns its temporary password once. `bootstrap-admin` does the same
for the first administrator, and `bootstrap-admin -link` links an administrator
created before revision 2 (keeping its role and authenticator). A
`super_admin` can reset another administrator's second factor
(`POST /admin/users/{id}/reset-credentials`, audited); the password is the
account's and is reset through the normal forgot-password flow.

## Revision 2: administrators are user accounts

Phase 1 first shipped a separate console login (own password on
`admin_credentials`, own form at `/admin/login`). Re-checking Tenable:

- **Tenable Security Center**: one user table and one login page. *Administrator*
  is a system-level role: the account belongs to no organization, cannot see
  organization data, and manages organizations, system configuration and SAML.
- **Tenable Vulnerability Management (cloud)**: one login; the customer's own
  Administrator configures SAML for their container. **MSSP portal**: the same
  login, then SSO into customer containers.

So two separate identity stores and two login forms were not the Tenable model.
What actually separates the tiers there is that the administrator account is in
no organization. Revision 2 adopts that: one account and one login, a database
guarantee that an administrator account is in no organization, TOTP before the
console, and no IdP path to the console. The console password, `/admin/auth/login`,
`/admin/auth/password`, `PLATFORM_ADMIN_EMAILS` and the tenant-context
`/api/v1/settings/{saml,identity-providers,verified-domains}` routes are removed.

## Revision 3: no admin API keys

Revision 2 still let every administrator row carry an API key (`X-Admin-API-Key`
or Bearer) with the same power as the console, no TOTP and no expiry, and it
generated and discarded one for every human administrator. With administrators
signing in as people, the key was only a second, weaker way in. Revision 3
removes it:

- `AdminAuthMiddleware` accepts only a verified console session.
- Removed: `POST /admin/users` (create by key), `POST /admin/users/{id}/rotate-key`,
  the `openctem-admin` CLI (its admin, audit-log and target-mapping commands
  are in the console), and the key fields on `AdminUser`.
- Migration 000227 revokes every key, deactivates rows with no linked account,
  and makes the key columns nullable; a later release drops them.
- `bootstrap-admin` creates only a person: the admin row and its sign-in
  account (temporary password printed once). It ships in the API image and the
  `admin-cli` image.

## Later phases

- **Phase 2 (api) — Organizations** (implemented, api#548; see the Organizations section of `docs/architecture/authorization-matrix.md`). Organization suspend is split out, since it needs enforcement at token exchange, the membership check and background jobs. `GET/POST /admin/tenants`, suspend/
  reactivate; per-organization SSO under `/admin/tenants/{id}/sso/*` (SAML,
  identity providers, verified domains, **SSO enforcement**, moved out of the
  tenant owner's `settings/security`); `TENANT_CREATION_MODE`; delete the dead
  `sso_enabled` / `sso_provider` / `sso_config_url` security fields (written,
  never read by the login path).
- **Phase 3 (ui) — console shell** (implemented, ui#505; sign-in reworked for
  rev. 2). A Tenable-style sidebar: Overview · Organizations · Users · Scanning
  (target mappings, platform tools) · System (Configuration, Diagnostics, Job
  queue, System logs, Keys). Replaces the transitional `(dashboard)/admin` pages.
- **Phase 4 — Entitlements.** Platform-set bundle ceiling per organization,
  fail-closed, that per-module overrides cannot exceed.

## Security notes

- The admin session cookie is scoped to `/api/v1/admin`, so it is never sent to
  tenant routes, and the tenant JWT never authenticates admin routes.
- Server-side sessions: deactivating an admin or resetting credentials deletes
  all of that admin's sessions immediately.
- All console outcomes (including refused SSO attempts) and credential changes
  are written to `admin_audit_logs`.
- A compromised organization account cannot become an administrator: linking
  needs a super admin, and an account with memberships cannot be linked.
