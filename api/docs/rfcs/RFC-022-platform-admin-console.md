# RFC-022 — Platform administration console (system admin)

> Status: **Accepted** (2026-09-30) — Phases 1-3 implemented (api#547, api#548, openctemio/ui#505).
> **Revision 2** (2026-09-30): the administrator is a user account signing in on
> the normal `/login` (see [Revision 2](#revision-2-administrators-are-user-accounts)).
> **Revision 3** (2026-10-01): administrators have no API keys (see
> [Revision 3](#revision-3-no-admin-api-keys)).
> **Revision 4** (2026-10-01): break-glass administrators and a platform-level
> identity provider for administrators (see
> [Revision 4](#revision-4-break-glass-administrators-and-the-platform-identity-provider)).
> **Revision 5** (2026-10-02): the platform administrator only bootstraps an
> organization's first owner (see
> [Revision 5](#revision-5-first-owner-bootstrap-only)).
> **Revision 6** (2026-10-02): organizations are created by the platform
> administrator by default, and the installer creates the first one (see
> [Revision 6](#revision-6-admin-only-organization-creation-and-the-first-organization)).
> **Revision 7** (2026-10-02): a suspended owner still blocks the first-owner
> bootstrap; a super admin's explicit owner recovery is the only exception (see
> [Revision 7](#revision-7-suspended-owners-and-owner-recovery)).

> **Revision 8** (2026-10-02): an organization's SAML / identity-provider
> change made in the console waits for an owner of the organization (see
> [Revision 8](#revision-8-sso-changes-wait-for-an-owner)).

> **Revision 9** (2026-10-08): an SSO domain is claimed by one organization,
> platform-wide (see [Revision 9](#revision-9-sso-domain-claims-are-exclusive)).

> **Revision 10** (2026-10-08): who may create an organization is a console
> setting, no longer only an environment variable (see
> [Revision 10](#revision-10-the-sign-up-policy-is-a-console-setting)).

> Scope: api + ui. Separates *application (platform) administration* from
> *organization (tenant) administration*: the system administrator is an account
> with a system-level role and a different menu (Organizations, Users, Scanning,
> System) from organization users.

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
| D1 | **Identity = a `users` account linked to `admin_users`** (rev. 2; originally `admin_users` alone). The account belongs to no organization (enforced in the database); `admin_users` holds the role (`super_admin` > `ops_admin` > `readonly`), the second factor, lockout and the admin audit trail. | One account table, one login page; the administrator role is system-level and belongs to no organization. Keeping the account out of every organization is what separates the tiers, not a second account table. `PLATFORM_ADMIN_EMAILS` is removed. |
| D2 | **Same backend.** Extend `/api/v1/admin/*`; no second service. | Admin operations (create org, assign bundles, configure SSO) need the same tenant/module/SSO services. A second service would duplicate logic or call back into the api. |
| D3 | **Console = password sign-in on `/login` + mandatory TOTP**, server-side console sessions. SSO/SAML sign-ins cannot open it. No admin API keys (rev. 3). | Admin sessions must be revocable (server-side), short-lived, and MFA-protected. No organization's IdP may authenticate a platform administrator. |
| D4 | **TOTP implemented in-house** (RFC 6238: HMAC-SHA1, 6 digits, 30 s, ±1 step), verified against the RFC test vectors. | No OTP library is in `go.mod`; ~50 lines is easier to audit than a new dependency on the admin auth path. Reusable later for tenant-user 2FA, which is also missing (the UI calls `/users/me/2fa`, which has no backend). |
| D5 | **Same Next.js app, separate shell** (own route group, layout, login, sidebar; shared `SidebarBrand`). | One application, a different menu per account type. Can be split into its own deployable later because the route group is independent. `/admin` + `/api/v1/admin` can be IP-restricted at the ingress. |
| D6 | **SCIM stays a tenant-admin feature** (api#546). | The tenant's own IT connects their IdP. |
| D7 | **Bundles become licensing only through a separate entitlement layer.** | Today a tenant admin's per-module "on" override beats the bundle baseline, and the module gate is fail-open, so locking bundle *subscription* alone would lock nothing. Entitlement (platform-set ceiling, fail-closed) ⊇ subscription (tenant) ⊇ toggles. OSS default: entitled to everything. |
| D8 | **Organization creation is a per-installation setting**, `TENANT_CREATION_MODE=self_service\|admin_only` (default `admin_only` since rev. 6; was `self_service`). | SaaS/trials need self-service; on-prem/enterprise wants admin-only. The platform admin can always create organizations. |

## Design — Phase 1: console authentication (api, as revised)

**Schema.** Migration `000225` added `admin_credentials` and `admin_sessions`;
`000226` (rev. 2) links administrators to accounts. The console password
columns (`admin_credentials.password_hash`, `password_changed_at`) are no longer
used; migration 001483 dropped them:

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
created before revision 2 (keeping its role and authenticator, and reactivating
it: migration 000227 deactivated every administrator without an account, which
is every v0.8 administrator). Without `-link`, such an administrator is refused
with a pointer to `-link` rather than reported as existing. A
`super_admin` can reset another administrator's second factor
(`POST /admin/users/{id}/reset-credentials`, audited); the password is the
account's and is reset through the normal forgot-password flow.

## Revision 2: administrators are user accounts

Phase 1 first shipped a separate console login (own password on
`admin_credentials`, own form at `/admin/login`). Two identity stores and two
login forms add attack surface without separating anything: what separates the
tiers is that the administrator account is in no organization, cannot see
organization data, and manages organizations, system configuration and SAML,
while each organization's own administrator configures SAML for that
organization. Revision 2 adopts that: one account and one login, a database
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

## Revision 4: break-glass administrators and the platform identity provider

Two decisions taken on 2026-10-01: `bootstrap-admin` also creates a backup
(break-glass) administrator, and administrators can sign in to the console
through a platform-level identity provider that is separate from every
organization's IdP.

References: Microsoft's emergency-access guidance (at least two accounts, not
federated, alert on every use, test regularly) and the common practice of keeping
a local administrator for when SSO is unavailable.

### Break-glass administrators

- **Schema** (migration 000229): `admin_users.is_break_glass`,
  `break_glass_tested_at`, `password_change_required`, and the IdP binding
  (`idp_issuer`, `idp_subject`, `idp_bound_at`). A `CHECK` forbids a binding on a
  break-glass row, so a break-glass administrator can never sign in through the
  IdP, whatever the application does. `admin_sessions.auth_method`
  (`password` | `idp`) and `admin_audit_logs.severity` are added.
- **Provisioning.** `bootstrap-admin -email=a@x -backup-email=b@x` creates both
  in one run: the primary `super_admin` and a `super_admin` marked break-glass,
  each with a new local account and a temporary password printed once. It is
  idempotent: an administrator that already exists is reported and skipped, so
  re-running it with `-backup-email` adds a backup to an existing install.
  `-backup-email` is required unless `-no-backup` is given explicitly. A super
  admin can also mark or unmark an administrator as break-glass in the console.
- **First use.** Both temporary passwords set `password_change_required`.
  After the TOTP step, a password-authenticated console session can call only
  `GET /auth/validate`, `POST /auth/password` and `POST /auth/logout` (403
  `PASSWORD_CHANGE_REQUIRED` otherwise) until the password is changed; TOTP
  enrollment is already mandatory. An IdP session is not held to this, since it
  did not use the password.
- **Every use is alerted.** When a break-glass administrator completes the
  console sign-in: an `admin_audit_logs` row `console.break_glass_sign_in` with
  severity `high`; a `WARN` log line with the stable field
  `alert=break_glass_sign_in` (for log-based alerting, the always-on channel);
  and an email to every other active administrator through the system SMTP
  sender (`SMTP_*`; skipped with a warning when it is not configured). There is
  no platform-level notification integration (integrations are per tenant), so
  email plus the log line is the channel.
- **Testing.** A test is a real sign-in with the break-glass account (which
  alerts like any other). Another super admin then confirms it on the
  Administrators page (`POST /admin/users/{id}/break-glass-test`), which records
  the sign-in time as `break_glass_tested_at`. The account cannot confirm its
  own test (four eyes), and the console flags a break-glass account that has
  not been tested for 90 days.
- **At least one way in remains.** The invariant, enforced server-side under a
  transaction-scoped advisory lock: there is always at least one active,
  linked `super_admin` who can sign in locally. While "require IdP" is in force,
  that means at least one break-glass `super_admin`. Deleting, deactivating,
  demoting or unmarking an administrator that would break it is refused (409),
  and so is turning on "require IdP" without a break-glass `super_admin`.

### Platform identity provider (OIDC)

- **Configuration** (`platform_identity_provider`, a single row, platform-level,
  not tenant-scoped): issuer, client id, client secret (AES-GCM via the
  application `Encryptor`; write-only, never returned), redirect URI, scopes,
  display name, enabled, `require_idp`, and the trusted `acr` / `amr` values.
  Managed by super admins at System → Admin sign-in
  (`GET/PUT/DELETE /api/v1/admin/platform-idp`), every change audited with
  severity `high`. On save the API fetches `{issuer}/.well-known/openid-configuration`,
  requires its `issuer` to equal the configured issuer exactly (OIDC Discovery
  4.3) and every endpoint to be `https`, and stores the authorization, token
  and JWKS endpoints. Discovery, JWKS and token requests use
  `httpsec.SafeHTTPClient` after `httpsec.ValidateURL`. The redirect URI is
  configured, never taken from a request, so there is no open redirect.
  Changing the issuer removes every administrator's IdP binding.
- **OIDC only.** SAML in this code base is tenant-shaped (per-organization
  metadata, ACS, JIT into tenant membership); reusing it for a platform IdP is
  not cheap, so it is left out. The protocol column exists for a later addition.
- **Separate from organizations.** The tenant `/login` page lists only the
  organization's providers (`/auth/providers`, per org slug); the platform IdP
  appears only on the console sign-in page, through
  `GET /api/v1/admin/auth/idp` (enabled + display name, nothing else). An
  organization's IdP still cannot open the console: `/auth/session` refuses any
  non-password `/login` session as before.
- **Flow** (authorization code + PKCE S256 + nonce + state):
  1. `POST /api/v1/admin/auth/idp/start` stores `sha256(state)`, the nonce and
     the encrypted PKCE verifier server-side (10-minute expiry, single use) and
     sets the state in an HttpOnly `admin_idp` cookie scoped to
     `/api/v1/admin/auth`. It returns the authorization URL (with `acr_values`
     when trusted `acr` values are configured).
  2. The IdP redirects to the console page `/admin/login/callback`, which posts
     `{code, state}` to `POST /api/v1/admin/auth/idp/callback`. The state must
     equal the cookie (constant time) and is consumed atomically
     (`DELETE ... RETURNING`), so it cannot be replayed or used from another
     browser.
  3. The code is exchanged with the client secret and the PKCE verifier. The
     `id_token` must verify against the JWKS (RS256/384/512, PS256, ES256), with
     `iss` equal to the pinned issuer, `aud` containing the client id (`azp`
     equal to it when there are several audiences), `exp` and `iat` within a
     two-minute leeway, a non-empty `sub`, and the nonce.
  4. **Matching, no JIT.** The administrator bound to (`iss`, `sub`) signs in.
     With no binding, an administrator whose email equals the token's email is
     bound on this first sign-in, only if the email is verified
     (`email_verified: true`, or Entra's `xms_edov: true`), the administrator
     is active, not break-glass, and not bound to another subject. After that,
     matching is by `iss` + `sub` only, never by email. An unknown identity is
     refused; nothing is created.
- **Second factor.** The default still requires the console TOTP after an IdP
  sign-in. Reason: the console cannot see how the IdP authenticated the user,
  and an IdP compromise or a weak IdP policy would otherwise be enough to reach
  every organization. A super admin can opt in to accepting the IdP's MFA by
  listing trusted `acr` values (sent as `acr_values` and required in the
  token's `acr`) and/or `amr` values (any one present in the token's `amr`).
  Only then does a matching token open a verified session directly. The
  session records `auth_method = idp`.
- **Require IdP.** With the IdP enabled and `require_idp` on, the local
  password path (`/auth/session`) is refused for every administrator except
  break-glass ones, and turning it on ends existing password sessions of
  non-break-glass administrators. The `/login` account itself is untouched,
  since it belongs to no organization and can open nothing without the console.
- **Rate limits.** `/idp/start` and `/idp/callback` use the auth limiter's
  token-exchange bucket (20/min per client IP); the TOTP step (`/mfa`) keeps
  the 5/min login bucket. Behind the UI's admin proxy every administrator
  reaches the API from the proxy's address, and one IdP sign-in makes three
  or four console auth calls, so the login bucket alone would let a single
  sign-in exhaust it for everyone.
- **Audit.** `console.idp_login` / `console.idp_login_failed` /
  `console.idp_bound` rows, with the reason server-side only. The client gets
  one generic "single sign-on failed" message.

## Revision 5: first-owner bootstrap only

The 2026-10-02 admin-plane review proved that an `ops_admin` could
`POST /admin/tenants/{id}/users {"role":"admin"}` into any existing
organization, receive the set-password link when SMTP was off (or use an email
it controls when it was on), sign in, and read the organization's findings,
credentials and audit log. That contradicts the model this RFC adopts:
the system administrator manages organizations but cannot see their data.
Owner decision, implemented here:

- **Bootstrap only.** `POST /admin/tenants/{tenantId}/users` creates the first
  owner of an organization that has **no owner** (active or suspended, since
  [revision 7](#revision-7-suspended-owners-and-owner-recovery)), and nothing else. An
  organization with an owner answers **409** ("its owner and administrators
  invite or create users themselves"). The request takes `email` and `name`;
  `role` may be omitted, anything but `owner` is a 400. The no-owner check and
  the insert run in one transaction under a per-organization advisory lock, so
  concurrent requests create one owner.
- **Delivery.** The account is created without a password; the owner chooses
  one through the one-time link, so the administrator never knows a password
  and the owner's first sign-in is with their own. (Tenant accounts have no
  temporary-password mechanism; `admin_users.password_change_required` is
  for console accounts. A password-less pending account plus a set-password
  link gives the same guarantee without one.) When the organization can send
  email (tenant or system SMTP) the link is **only emailed** and never returned
  — a failed send is reported as `email_failed` and the owner uses
  forgot-password; it does not fall back to handing the link over. Only when
  email cannot be sent at all is `setup_token` returned, once. That exception is
  allowed for this bootstrap case alone: without SMTP there is no other way to
  reach the new owner, and the organization has nobody who could invite them.
  The owner created with `POST /admin/tenants` follows the same rule.
- **Audit.** Besides `admin_audit_logs`, the creation is written to the
  organization's own audit log (`user.created`, `bootstrap_owner: true`,
  actor `platform-admin:<email>`, severity high), so the owner sees how their
  account came to exist.
- **Console.** The organization's Users section offers "Create first owner"
  only while the organization has no owner; otherwise it explains that the
  owner and administrators invite users themselves.

Not changed: a lost or departed owner still has no recovery path short of SQL
(no ownership transfer, no "assign owner" for an organization whose owner
exists). That is a separate decision.

## Revision 6: admin-only organization creation and the first organization

Owner decision 2026-10-02 ("admin-only + setup creates the first org").

- **Default `TENANT_CREATION_MODE=admin_only`.** Organizations are created by
  the platform administrator: the console (`POST /admin/tenants`) or
  `bootstrap-admin -org-*` at install. `self_service` (create-first-team and
  `POST /tenants` for any signed-in user) is an explicit opt-in for SaaS and
  trial installs. The check fails closed: anything but `self_service`,
  including an unset mode in a configuration built in code, is admin-only.
  Existing organizations are unaffected.
- **The installer creates the first organization.** A platform administrator
  belongs to no organization (revision 2), so a fresh install had no one who
  could use the product until an administrator created an organization in the
  console. `bootstrap-admin` takes `-org-name`, `-org-slug` (derived when
  empty), `-org-owner-email` and `-org-owner-name` and creates it through
  `tenantapp.OrganizationCreator`, the service the console's create path uses:
  organization, owner membership and owner role in one transaction;
  `tenant.created` and (for a new owner account) `user.created` audited in the
  new organization with actor `bootstrap-admin`; a one-time set-password link
  for a new owner under the revision 5 first-owner rule: emailed when the
  organization can send email (never printed then; a failed send is reported
  and the owner uses forgot-password), otherwise printed once by the command.
  An existing slug is reported and left alone, so re-running is safe; the
  System tenant's slug is refused; an administrator's email cannot own it.
- **`bootstrap-tenant` is removed.** It wrote users, tenants, memberships and
  roles with raw SQL, audited nothing, ignored the creation mode and took the
  owner's password on the command line. The Helm chart's `api.bootstrapTenant`
  Job is removed with it (the chart refuses to render if it is still enabled).
- **Self-service paths are audited.** `create-first-team` now writes the
  organization and owner atomically (`CreateWithOwner`, like the other paths)
  and audits `tenant.created`; `POST /tenants` already did. The UI no longer
  pre-fills "<Name>'s Team", which produced personal organizations.

First install: migrations → `bootstrap-admin -email … -backup-email …
-org-name … -org-owner-email …` → the administrator signs in on `/login`,
changes the temporary password and enrolls TOTP in `/admin` → the owner sets a
password through the link → the owner adds users; the administrator configures
the organization's SSO in the console.

## Revision 7: suspended owners and owner recovery

Revision 5 counted only **active** owners, so an organization whose owner was
suspended looked owner-less: an `ops_admin` could create a new owner for an
organization full of data and, without SMTP, receive its set-password link,
which is the takeover revision 5 set out to prevent. Owner decision
2026-10-02, implemented here:

- **Any owner blocks the bootstrap.** An owner membership (by the `owner`
  label or the system owner role), active **or suspended**, makes
  `POST /admin/tenants/{tenantId}/users` answer 409. The check and the insert
  stay in one transaction under the per-organization advisory lock.
- **Explicit owner recovery.** When every owner is suspended nobody can
  manage the organization, so the same endpoint takes `"recovery": true`:
  - **super_admin only.** Any other console role gets 403. The route itself
    stays ops_admin+, and the handler checks the role for a recovery request.
  - **Only while no owner is active.** An active owner answers 409, with or
    without the flag.
  - **Email only.** The set-password link is emailed and **never** returned,
    even when no SMTP is configured: the request is then refused with 400
    before anything is created (configure SMTP first). A failed send is
    reported as `email_failed` and the new owner uses forgot-password. The
    administrator therefore never holds a credential for an organization that
    has data.
  - **Audited twice.** The admin audit row is written as
    `organization.owner_recovery` at high severity, including refused
    attempts. The organization's audit log gets `user.created` at **critical**
    severity with `owner_recovery: true`, by actor `platform-admin:<email>`.
- The suspended owners are left as they are. The new owner (or an
  administrator they appoint) decides whether to reactivate or remove them.
- **Reason and step-up** (revision 14). The request also needs a `reason`
  (10 to 500 characters, kept in the admin audit row) and a fresh console
  authenticator code (`totp_code`). Organizations > an organization >
  Members offers "Recover ownership" to a super admin when every owner is
  suspended.

Still not provided: ownership transfer, or recovery for an organization whose
owner is active but unreachable. Those need the owner's own action.

## Revision 8: SSO changes wait for an owner

Owner decision 2026-10-02. The organization's SAML configuration and OIDC
identity providers decide who can sign in to it. A platform administrator who
could change them directly could install their own IdP signing certificate (or
their own OIDC client with auto-provisioning) and sign in as any member of the
organization. So the console only **proposes** such a change:

- **What waits.** `PUT /admin/tenants/{id}/sso/saml`,
  `POST /admin/tenants/{id}/sso/identity-providers` and
  `PUT /admin/tenants/{id}/sso/identity-providers/{idpId}` answer **202** with
  the stored change (`sso_pending_changes`, migration 000273). The live config
  is untouched. The request is validated first (certificate, roles, domains,
  provider type), so a bad config is refused at once with 400, and a second
  provider of the same type with 409.
- **What does not wait.** Deleting a SAML config or an identity provider, SSO
  enforcement and verified domains apply directly: none of them adds a way to
  sign in as someone.
- **Bootstrap.** An organization with **no active owner** has nobody to
  approve, so a change to it applies directly (200/201), as before. This is the
  same "no owner yet" test as the revision 5 first-owner rule; once the first
  owner exists, every later SAML/IdP change waits.
- **Who is told.** Every active owner gets an in-app notification
  (`sso_change_pending`, severity high) and, when system SMTP is configured, a
  security email. Both describe the change (IdP entity, sign-in URL, the
  certificate's SHA-256, client ID, auto-provision) and never a secret.
- **Deciding.** Owner only:
  `GET /tenants/{t}/settings/sso/changes`,
  `POST /tenants/{t}/settings/sso/changes/{id}/approve|reject`
  (`RequireTeamOwner`, and the service re-checks in the database that the
  caller is an active owner of that organization). Approval marks the row
  approved and writes the live config **in one transaction**, so two owners
  approving at once apply it once, and a failed write leaves it pending.
  Rejection discards it. Both are written to the organization's audit log
  (`sso.change_approved` / `sso.change_rejected`, severity high); the
  submission is `sso.change_requested`, actor `platform-admin:<email>`.
- **Lifetime.** A change expires after **7 days** (410 on approve). A newer
  submission for the same SAML config / provider supersedes the older one
  (409 on approve), so an owner never applies a stale proposal.
- **Secrets.** An OIDC client secret is stored encrypted (same key as
  `tenant_identity_providers`), separate from the payload, never returned, and
  cleared when the change is decided.
- **Console.** The SAML and identity-provider forms report "submitted for
  approval" and the organization's SSO tab lists what is pending
  (`GET /admin/tenants/{id}/sso/changes`). Owners decide on
  Settings › SSO approvals (`/settings/sso-approvals`), linked from the
  notification.

## Revision 9: SSO domain claims are exclusive

The verified domains a platform administrator sets up for an organization are
what let its IdP admit people (JIT, SAML for existing members, the Google
Workspace `hd` check). Two organizations holding the same verified domain
would both admit its people, so a claim is now exclusive, platform-wide:

- verifying a domain that another organization holds answers 409 without
  naming it; the row stays pending;
- after the holder's DNS proof lapses, another organization waits 7 days
  before it can verify;
- public suffixes (including private-section ones such as `github.io`),
  consumer mailbox providers and disposable-address services cannot be added;
- rows that two organizations had verified before this revision keep working,
  flagged `claim_conflict`; the console shows a "Claim conflict" badge and the
  administrator removes the wrong one.

Details: `docs/architecture/sso-authentication.md`, "Domain claims are
exclusive".

## Revision 10: the sign-up policy is a console setting

`TENANT_CREATION_MODE` (revision 6) could only be changed by redeploying, and
nothing in the console showed it. It is now the platform setting
`signup_policy`, on System > Sign-up:

- `admin_only` (default) or `self_service`, plus whether people may request
  access;
- the environment variable seeds it on the first start; the stored value wins
  afterwards;
- any administrator reads it; a super admin changes it with a fresh
  authenticator code and the version read; every change is audited at
  critical severity and emailed to the other administrators;
- a read failure means `admin_only`; a change never touches existing
  organizations, users or sessions.

With request access on, people who cannot sign up may ask for an
organization; Organizations > Access requests lists them, and approving one
creates the organization with the requester as owner (ops_admin+, audited).

Details: `docs/architecture/user-onboarding.md`, "Sign-up policy" and
"Request access".

## Revision 11: plans and limits

Organizations are on a plan (Free, Pro, Enterprise) that caps what they may
add:

- System > Plans: the plan defaults; any administrator reads them, a super
  admin changes them with a fresh authenticator code and the version read,
  audited at critical severity and emailed to the other administrators;
- Organizations > an organization: its plan, usage, an over-limit badge, and
  per-organization overrides (reason required, optional expiry), ops_admin+,
  audited;
- lowering a limit never removes members, assets or keys: new additions are
  refused until usage is under it again;
- organizations created before plans are Enterprise (unlimited); a
  self-service organization starts on Free.

Details: `docs/architecture/plans-and-limits.md`.

## Revision 12: idle Free workspaces

A Free organization nobody signs in to is reminded at 60 days, read-only at
90 (changes refused, reads and exports kept), warned again at 113 and due for
deletion at 120; a sign-in by any member undoes it at once. The platform
administrators are alerted at deletion_due and delete from the console;
nothing is deleted automatically. Organizations > an organization shows the
stage and lets an ops_admin+ exempt it with a reason (audited).

Details: `docs/architecture/idle-workspaces.md`.

## Revision 13: console layout, overview and search

The console is organized by what an operator does, and opens on what needs
them:

- **Navigation.** Overview · Customers (Organizations) · Scanning (Target
  mappings) · Security (Admin activity, Administrators) · System (Sign-up,
  Admin sign-in, Plans). Later sections (Users, Requests, Plans & usage, Operations)
  are added together with their pages, never ahead of them. Pages that moved
  (`/admin/system-logs` to `/admin/security/activity`, `/admin/administrators`
  to `/admin/security/administrators`) have no redirect.
- **Overview = attention queue.** `GET /api/v1/admin/overview` (any admin
  role) returns counts: organizations and those without an active owner (with
  the names of the newest five), emergency-access sign-ins in the last 7 days,
  refused or failed administrator actions in the last 24 hours, overdue
  break-glass tests, the applied database schema against the one the API
  ships (and the dirty flag), platform sensors online and offline, pending
  sensor jobs and the oldest one's age, scan runs past their deadline, and
  failed and dead notifications. The web turns them into a list, most severe
  first, each with its one-click action when a console page handles it (a
  link is offered only to a role that can act on it). The response carries no
  tenant content and no administrator email; the roster stays super-admin
  only. It refreshes every minute.
- **Search.** Ctrl/Cmd+K opens the console's command palette: the pages the
  role can open, and organizations by name or slug, searched on the server.
- **Admin activity** filters by result (`?outcome=failure`), so the overview
  links straight to refused actions or to break-glass sign-ins.

## Revision 14: organization 360

Organizations > an organization opens on a summary: owners and active
members, the plan with an over-limit badge and the limits that are over,
sign-in (SSO posture and verified domains), identifiers, and the latest
administrator actions on it. Each card leads to its tab. The tab is in the
URL (`?tab=overview|users|plan|sso|activity|audit-chain`), so a support link
can point at one. Activity lists every admin audit row about the
organization (`GET /admin/audit-logs?resource_id=<id>`).

The organization list shows each organization's plan and filters by owner
(`owner=none` lists those with no active owner, which the overview links
to) and by plan. Owner recovery gained a reason and step-up (revision 7).
Nothing from inside an organization (findings, assets) is shown: the console
never reads it.

## Revision 15: Users (cross-organization account support)

Customers > Users finds an account in any organization and helps it sign in
again, without touching what an organization holds:

- `GET /api/v1/admin/platform-users?q=` (any admin): accounts whose email or
  name contains `q` (3 characters at least; the directory is looked up, not
  browsed), or whose id is `q`. Each shows its sign-in state: provider,
  verified email, lockout, failed sign-ins, MFA, last sign-in, how many
  organizations it is in, and whether it is a platform administrator or
  erased.
- `GET /api/v1/admin/platform-users/{user_id}` (any admin, **audited** as
  `platform_user.view`): the account, its organizations (name, role,
  membership status), its federated identities (issuer, subject) and its
  active sessions (IP, method, started, last seen).
- Support actions, **ops_admin+**, a `reason` of 10 to 500 characters
  (kept in the admin audit row), 20 per minute per administrator, audited as
  `platform_user.<action>` with the account as resource:
  `revoke-sessions` (every session, every organization), `unlock` (clears
  the failed-sign-in lockout), `password-reset` (the forgot-password link,
  emailed to the account; accounts with a password only), and
  `verification-emails` (a new link; the old one stops working). Links go to
  the account's own mailbox and are never returned; without SMTP the email
  actions answer 409 `EMAIL_UNAVAILABLE`.
- Refused with 409 for a platform administrator's account (managed in
  Security > Administrators, so an operations administrator cannot sign a
  super admin out) and for an erased account.
- Ctrl/Cmd+K also finds accounts.

## Revision 16: security center

- **Sessions** (Security > Sessions, super admin only, like the roster):
  `GET /api/v1/admin/console-sessions` lists every open console session (the
  administrator, role, break-glass, how they signed in, IP, started, last
  seen; the caller's own is marked). `DELETE /api/v1/admin/console-sessions/{id}`
  ends one at once: a reason (10 to 500 characters) and a fresh authenticator
  code, audited at high severity as `console.session_ended`. The caller's
  own current session is refused (sign out instead).
- **Admin activity** gained a date range (`from`/`to`), a detail sheet per
  entry (resource, request, browser, error, and the request body as stored,
  secrets redacted) and a CSV export of the filtered page (formula-safe
  cells).
- One step-up check (`confirmAdminStepUp`) serves owner recovery and ending
  a session.

## Revision 17: operations

Operations > Health (`GET /api/v1/admin/operations`, any admin role) shows
the installation as the API sees it, without Prometheus:

- the build (version, commit, channel) and the applied database schema
  against the one this release ships (behind, ahead, dirty);
- the database (ping latency, the API's connection pool) and Redis (ping
  latency, or "not configured");
- the work queues: sensor jobs waiting and running and the oldest waiting
  job, open scan runs and those past their deadline, notifications waiting,
  retrying and given up;
- active sensors, platform and customer, by health and SDK version, with
  versions below the configured minimum flagged;
- background jobs: each controller's last run, its errors since start, and
  whether its loop is started (read from the API's own metrics registry).

Platform-wide counts and infrastructure facts only. The overview's
platform items (schema, sensors, runs, notifications, waiting jobs) link to
it.

## Revision 18: system settings, announcements and feeds

- **System > Announcements.** The operator publishes a notice (planned
  maintenance, a warning, information) that every signed-in user sees as a
  dismissible banner under the header while it is active.
  `GET/POST /api/v1/admin/announcements` (any admin reads; ops_admin+
  publishes with a reason, audited) and
  `POST /api/v1/admin/announcements/{announcement_id}/cancel` (ops_admin+,
  reason, audited; a scheduled one never shows). A notice is one line of
  plain text (1-500 characters, no control characters, rendered as text,
  never HTML) with a required end at most 31 days after its start, so none
  is left up by mistake. Signed-in users read the active ones (at most 5,
  maintenance first) at `GET /api/v1/announcements`, once per page load.
  Table `platform_announcements` (migration 001492), platform-level.
- **System > Threat intelligence.** The EPSS and CISA KEV feeds' sync state
  (last run, records, next run, last error), turning the scheduled sync on
  or off and running a sync now, on the existing
  `/api/v1/admin/threat-intel/sync` routes (ops_admin+ for changes,
  audited).

## Later phases

- **Phase 2 (api) — Organizations** (implemented, api#548; see the Organizations section of `docs/architecture/authorization-matrix.md`). Organization suspend is split out, since it needs enforcement at token exchange, the membership check and background jobs. `GET/POST /admin/tenants`, suspend/
  reactivate; per-organization SSO under `/admin/tenants/{id}/sso/*` (SAML,
  identity providers, verified domains, **SSO enforcement**, moved out of the
  tenant owner's `settings/security`); `TENANT_CREATION_MODE`; delete the dead
  `sso_enabled` / `sso_provider` / `sso_config_url` security fields (written,
  never read by the login path).
- **Phase 3 (ui) — console shell** (implemented, openctemio/ui#505; sign-in reworked for
  rev. 2). A sidebar: Overview · Organizations · Users · Scanning
  (target mappings, platform tools) · System (Configuration, Diagnostics, Job
  queue, System logs, Keys). Replaces the transitional `(dashboard)/admin` pages.
- **Platform sensors belong to the console only** (research/67, 2026-10-07).
  On the tenant plane a platform sensor does not exist: every
  `/api/v1/sensors/{id}...` route answers 404 for it (one guard,
  `SensorHandler.OwnSensor`), lists and counts leave it out, and a
  tenant sees platform scanning only as a service
  (`GET /api/v1/platform/scanning`: regions, state, tools, its own jobs).
  Console pages to list, drain, re-key and retire platform sensors are not
  built yet (Scanning section, a later phase).
- **Phase 4 — Entitlements.** Platform-set bundle ceiling per organization,
  fail-closed, that per-module overrides cannot exceed.
- **Audit chain per organization** (implemented, owner-approved 2026-10-02).
  Organizations → an organization → Audit chain classifies the organization's
  audit hash-chain with the same code as `cmd/chainaudit` and lets a super
  admin rebaseline it only when every break is explained, the chain is the one
  reviewed, and a fresh console TOTP code is entered (the console's first
  step-up). See `docs/architecture/audit-hash-chain.md`.

## Security notes

- The admin session cookie is scoped to `/api/v1/admin`, so it is never sent to
  tenant routes, and the tenant JWT never authenticates admin routes.
- Server-side sessions: deactivating an admin or resetting credentials deletes
  all of that admin's sessions immediately.
- All console outcomes (including refused SSO attempts) and credential changes
  are written to `admin_audit_logs`.
- Irreversible actions take a step-up (`adminconsole.Service.StepUp`): a fresh
  code from the console authenticator, single use (the sign-in replay guard),
  counted toward lockout when wrong, audited as `console.step_up` /
  `console.step_up_failed`. An administrator with no enrolled authenticator
  (IdP-only sign-ins) gets 403 `STEP_UP_UNAVAILABLE`. First used by the audit
  chain rebaseline.
- Provisioning never links an existing account: it always creates a new one
  and refuses an email that already has an account. With self-registration an
  attacker could otherwise pre-register an administrator's email, own its
  password, and enroll their own TOTP on first use (found in the 2026-10-01
  review).
- The console cannot change who can sign in to an organization that has an
  owner: SAML and identity-provider changes wait for an owner's approval
  (revision 7).
- The console checks on every request that the linked account can still sign
  in, so suspending the account ends console access at once.
- Administrators change their own password in the console
  (`POST /admin/auth/password`); the change ends every `/login` and console
  session of the account.
- An administrator cannot deactivate, demote or delete themselves, so the
  super admin making a change always remains: the platform is never left
  without an active super admin.
