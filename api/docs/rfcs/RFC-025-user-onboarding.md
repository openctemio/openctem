# RFC-025 — User onboarding: administrators create users, SSO admits them

> Status: **Accepted** (2026-10-01) — implemented.
> Scope: api + ui. Builds on RFC-022 (platform admin console) and the SSO
> verified-domain work (`docs/architecture/sso-authentication.md`).
> Operator guide: `docs/architecture/user-onboarding.md`.
> **Update 2026-10-08:** `AUTH_ALLOW_REGISTRATION` is retired. Who may sign up
> is the console sign-up policy (RFC-022 revision 10), and every path that
> creates an account or an organization applies one admission rule
> (`signup.Admit`; user-onboarding.md, "Admission"). The default is unchanged:
> no self-registration.

## Decision

> "No self-registration. At setup there is one platform admin; that admin uses
> the system and creates users; users cannot register themselves. For an
> organization, SSO decides whether a user is admitted."

So a person gets an account in exactly one of these ways:

| Way in | Who decides | Password |
|--------|-------------|----------|
| Created by an organization owner/admin (Settings → Users → Add user) or by the platform administrator (console → Organizations → Users, or as the owner of a new organization) | That administrator | Set by the user through a one-time link |
| Invitation accepted (existing account, or registers with the invitation token) | The inviting owner/admin | Chosen by the user at registration |
| Organization SSO (OIDC or SAML) just-in-time provisioning | The organization's SSO configuration (platform administrator) | None (federated) |
| Self-registration (`AUTH_ALLOW_REGISTRATION=true`) | Nobody (open) | Off by default; for trial instances only |

## Problem (verified on develop, 2026-10-01)

1. `AUTH_ALLOW_REGISTRATION` defaulted to **true**. Open registration combined
   with other flows has caused escalations before (api#552: invitation tokens
   readable by any member + open registration = viewer → admin).
2. Administrators could not create users: invite-only, and the invitee needed
   open registration to get an account.
3. An invitation with only the RBAC **viewer** role created a **member**
   membership. `tenant_members.role` is copied into `user_roles` by a trigger,
   so the invitee also got the system member role. On top of that,
   `cmd/server/main.go` rebuilt the tenant service without its role service, so
   `POST /invitations/{token}/accept` dropped the invitation's role ids entirely.
4. SSO JIT: brand-new OIDC users were refused whenever registration was off
   (SSO could not admit anyone with the secure setting); SAML created a user
   and a tenant-less session even with auto-provisioning off and never checked
   the verified-domain gate; a missing domain verifier fell back to the
   admin-asserted allow-list; the default JIT role was `member`.
5. `Security.AllowedDomains` and `Security.IPWhitelist` were stored and shown
   in Settings but **never enforced** — a false sense of safety.

## Design

### 1. Self-registration off by default

- `AUTH_ALLOW_REGISTRATION` default `false` (config, `.env.example`, compose).
  The Helm chart does not set it, so it inherits the new default.
- `POST /auth/register` returns a generic **403 "Registration is not
  available"** unless the body carries `invitation_token` of a **pending**
  invitation addressed to the **same email** whose organization admits that
  email domain. Any other token (unknown, expired, other email) gets the same
  403, so the response reveals nothing about tokens. An invited registration is
  email-verified (the invitation was delivered to that address).
- `GET /auth/providers` reports `registration_enabled`; the UI hides sign-up
  unless it is true or the visitor came from an invitation.
- `TENANT_CREATION_MODE` is unchanged here (RFC-022 D8; its default became
  `admin_only` in RFC-022 revision 6): with `admin_only`, both
  `POST /tenants` and `POST /auth/create-first-team` return 403. With
  registration off, self-service creation is still only reachable by people
  who already have an account.

### 2. Administrators create users

`POST /api/v1/tenants/{tenant}/users` (`RequireTeamAdmin`), body
`{email, name, role_ids[1..10]}`:

- Refuses an email that already has an account (**409**, "invite them
  instead"): attaching an existing account needs its owner's consent, and
  creating over it would let an administrator seize it.
- Refuses an email outside `Security.AllowedDomains` (400) and the owner role.
- Same anti-escalation as invitations (a non-admin caller may grant only roles
  whose permissions they hold).
- Creates a local account **without a password** (`NewProvisionedLocalUser`,
  email verified on the administrator's word), a membership whose coarse role is
  derived from the roles (below), and sets exactly `role_ids` as the user's RBAC
  roles.
- Issues a **one-time set-password link**: 32-byte random token, only its
  SHA-256 stored (the password-reset token column), single use (consumed by
  `POST /auth/reset-password`, which clears it first), **24 h** TTL. Emailed when
  the organization (tenant SMTP integration) or the platform (system SMTP) can
  send email; otherwise, or if sending fails, returned **once** as
  `setup_token` in the 201 response to the creating administrator
  (`Cache-Control: no-store`). It is never listed or returned anywhere else.
- `POST /tenants/{tenant}/users/{userId}/setup-link` issues a fresh link
  (invalidating the old one) **only** for an account that is still pending
  (local, no password, never signed in) **and** belongs to this organization
  only. Any other account belongs to its owner (forgot-password); handing its
  set-password link to an organization administrator would let them take it
  over.
- `GET /tenants/{tenant}/members` items carry `pending_setup`.

Platform administrator (console session):

- `GET/POST /api/v1/admin/tenants/{tenantId}/users` (POST: ops_admin+, audited;
  since RFC-022 revision 5 it creates only the first owner of an organization
  that has none)
  reuse the same service, with a built-in role (`admin|member|viewer`).
- `POST /api/v1/admin/tenants` accepts an `owner_email` with no account (plus
  optional `owner_name`): the owner's account is created, the organization is
  created with it, and `owner_setup` carries the link outcome.

### 3. Invitations without open registration

- An invited person without an account registers with the invitation token (see
  1), signs in, and accepts.
- The invitation's **membership role is derived from its RBAC roles**
  (`MembershipRoleForRoleIDs`): `member` if they include the system member or
  admin role, otherwise `viewer`. On accept, the invitation's roles become the
  user's **exact** RBAC role set (`GrantExactRoles` → `SetUserRoles`), replacing
  the system role the trigger inserted. Invitations stored before this change
  (role `member`) are accepted with the derived role too.
- The owner role can no longer be put on an invitation.
- `main.go` re-wires `SetRoleService` / `SetUserService` after rebuilding the
  tenant service.

### 4. SSO admits users (JIT)

One rule for OIDC (`ensureTenantMembership` / `findOrCreateUser`) and SAML
(`CompleteFederatedLogin`): a person who is not yet a member is admitted only
when **all** hold — the organization's provider is active and auto-provisions;
the email domain is a **DNS-verified domain** of the organization (no verifier
or a lookup error refuses); the provider's own allowed domains (if any) contain
it; the organization's `Security.AllowedDomains` (if any) contains it. The check
runs **before** an account is created, so a refused login leaves nothing behind
and gets a generic 403 ("You do not have access to this organization"). Per-org
SSO no longer depends on `AUTH_ALLOW_REGISTRATION`; global social sign-in
(Google/GitHub/Microsoft without an organization) still does.

Default JIT role is **viewer**: the identity-provider entity default,
`SSO_ENTRA_DEFAULT_ROLE`, and SAML's empty default. The platform administrator
sets it per organization (`default_role` on the identity provider / SAML
config, `admin|member|viewer`; `owner` is never granted). On each login only
the display name is re-synced; email, password, roles and memberships never
change through a login.

### 5. `AllowedDomains` and `IPWhitelist` enforced

- **AllowedDomains** (exact domain after `@`, case-insensitive; empty = no
  restriction): invitation create and accept, invited registration,
  administrator-created users, `AddMember` (also used by SCIM provisioning), SSO
  JIT (OIDC and SAML).
- **IPWhitelist** (IPs or CIDRs; empty = no restriction): `IPAllowlistGate` on
  every request authenticated with a **user access token**, for the organization
  the request acts on (URL `/tenants/{tenant}` when present, else the token's
  organization). Not applied to sensor/agent or tenant API keys, the platform
  admin console, or public routes. Client IP from `httpsec.ClientIP`
  (forwarding headers honored only from `SERVER_TRUSTED_PROXIES`). 403
  `IP_NOT_ALLOWED`; policy cached 30 s per organization, invalidated on save;
  lookup error fails closed.
- **Lockout guard**: `PATCH /tenants/{t}/settings/security` refuses (400) an
  `ip_whitelist` that does not include the caller's current IP, which the
  settings response reports as `security.current_ip`.

### Also fixed (found while verifying end to end)

- **SAML sign-in could never succeed**: the ACS handed the request to crewjam
  without `ParseForm`, and crewjam reads `SAMLResponse` from `r.PostForm`, so
  every signed response was rejected as "invalid xml: no root". The ACS now
  parses the (1 MB-capped) form. Regression test: a real crewjam-signed response.
- **Used/expired reset (and set-password) links returned 500**: the repository
  reports them as `user.ErrInvalidPasswordResetToken`, which `ResetPassword`
  (and `VerifyEmail`, for its token) did not map. Now 400 "invalid or expired".
- **Emailed reset links pointed at `/auth/reset-password`**, a UI route that does
  not exist; they now point at `/reset-password`.

## Alternatives rejected

- **Admin-chosen password emailed to the user**: puts a reusable credential in
  the administrator's hands and in mailboxes. A one-time link has neither
  problem.
- **Creating over an existing account / auto-adding it**: account takeover by
  an organization administrator; invitations already handle existing accounts.
- **Owner break-glass for the IP allowlist**: the allowlist exists to stop
  stolen credentials from elsewhere, including an owner's. The save-time guard
  plus the documented recovery is the safety net instead.
- **Letting SSO JIT bind an existing non-member account**: unchanged — SAML
  still requires an existing account to be a member already (cross-tenant
  assertion forging); OIDC adoption keeps the proof-before-link rules.

## Security notes

- `setup_token` is a credential: shown once, `no-store`, never logged, hashed
  at rest, replaced on reissue, consumed on use.
- Without SMTP the platform cannot prove email ownership for any flow; an
  administrator who receives a link can set that account's password. This is
  the same trust as invitations without SMTP, and is limited by
  `AllowedDomains` and by refusing existing accounts.
- The IP allowlist is only as good as the client IP: behind the UI's Next.js
  proxy the API sees the UI container unless `SERVER_TRUSTED_PROXIES` includes
  it and the UI forwards the client IP (`TRUST_PROXY_HEADERS=true`, which must
  only be set behind a reverse proxy that overwrites `X-Real-IP` /
  `X-Forwarded-For`). Misconfiguration shows up at save time: the lockout guard
  reports the IP the server sees.
