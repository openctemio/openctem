# SSO Authentication (per-tenant + platform fallback)

> How OpenCTEM authenticates users against external identity providers, and how
> the **Microsoft Entra ID** login resolves its configuration: a tenant's own
> config first, then a platform-wide env fallback.
>
> **Setting up Entra ID as an operator?** See the step-by-step how-to:
> [`../how-to/configure-entraid.md`](../how-to/configure-entraid.md) (Azure app
> registration, env vars, `xms_edov`, verified domains, troubleshooting). This
> document is the design/rationale reference.

## Two distinct "Microsoft" login paths

These are independent — don't confuse them:

| Path | Code | Config source | Endpoint | Use |
|------|------|---------------|----------|-----|
| **Global Microsoft OAuth** | `internal/app/auth/oauth.go` | `OAUTH_MICROSOFT_*` env | `login.microsoftonline.com/common/…` | A generic "Sign in with Microsoft" social button, not tenant-scoped. |
| **Per-tenant Entra ID SSO** | `internal/app/auth/sso.go` | tenant DB record **or** `SSO_ENTRA_*` env fallback | `login.microsoftonline.com/{directory}/…` | Enterprise SSO into a specific org (slug), with auto-provisioning + domain restriction. |

This document covers the **SSO** path.

## Per-tenant SSO

Providers supported: `entra_id`, `okta`, `google_workspace`
(`pkg/domain/identityprovider`). Each tenant stores its own
`IdentityProvider` row (client id, encrypted client secret, directory/issuer,
scopes, allowed domains, auto-provision, default role).

Flow (`SSOService`):
1. `GET /api/v1/auth/sso/providers?org={slug}` → active providers for the org's
   login page.
2. `GET /api/v1/auth/sso/{provider}/authorize?org={slug}&redirect_uri=…` →
   builds the IdP authorize URL with a signed **state** (HMAC over org+provider+
   nonce) for CSRF/replay protection.
3. `POST /api/v1/auth/sso/{provider}/callback` → validates state, exchanges the
   code for tokens, fetches userinfo, enforces the email-domain allow-list,
   finds/creates the user, auto-provisions tenant membership (if enabled), and
   issues an OpenCTEM session.

**Who SSO admits (RFC-025).** For an organization, SSO decides whether a person
is admitted. Someone who is not yet a member is provisioned just-in-time only
when the provider is active and auto-provisions, the email domain is a
DNS-verified domain of the organization (no verifier or a lookup error
refuses), the provider's allowed domains (if any) contain it, and the
organization's `Security.AllowedDomains` (if any) contains it. This is checked
before an account is created; a refused login gets a generic 403 and leaves no
account behind. It does not depend on `AUTH_ALLOW_REGISTRATION` (which still
governs the global social sign-in buttons). JIT members get the provider's
`default_role` (`admin|member|viewer`, default **viewer**, set by the platform
administrator); only the display name is re-synced on later logins.

Security: outbound calls use `httpsec.SafeHTTPClient` (refuses loopback/RFC1918/
link-local), Entra/Graph hosts are fixed strings, an email is required, and the
email domain is checked against the provider's allow-list.

## Who may configure SSO (platform administrator only)

Configuring an organization's SSO is a **platform-administrator** operation, not
a tenant one: SAML and OIDC federation is system-level configuration, not an
organization user's setting. An organization owner or admin cannot set up SSO
for their own organization.

A platform administrator is a normal user account that belongs to no
organization and is linked to an `admin_users` row (RFC-022). They sign in on
the same `/login` page with their password, then open the admin console with a
TOTP code. The console refuses a session created by SSO/SAML, so an
organization's identity provider can never authenticate an administrator.

### Per-organization SSO in the admin console (RFC-022 Phase 2)

The platform admin console configures SSO **per organization** under
`/api/v1/admin/tenants/{tenantId}/sso/*` (SAML, identity providers, verified
domains, enforcement), authenticated as the admin identity (console session or
API key). The former tenant-context `/api/v1/settings/{saml,identity-providers,verified-domains}`
routes and the `PLATFORM_ADMIN_EMAILS` flag were removed.

**SSO enforcement** (`sso_enforced`) moved with it. The organization owner can
still see it in `GET /tenants/{t}/settings` but can no longer change it: the
tenant PATCH returns 403, and the admin endpoint keeps the "a usable SSO path is
required" guard. The owner break-glass at login is unchanged. The
`sso_enabled` / `sso_provider` / `sso_config_url` security fields were removed:
they were written but never read by the login path.

### Changes wait for an owner of the organization (RFC-022 revision 8)

The platform administrator configures SSO, but cannot change who can sign in to
an organization that already has an owner. A SAML config save
(`PUT .../sso/saml`) or an identity-provider create/update
(`POST`/`PUT .../sso/identity-providers`) is stored as a pending change
(`sso_pending_changes`, 202) and every active owner is notified (in-app
`sso_change_pending`, plus email when SMTP is configured; never a secret). An
owner approves or rejects it under Settings › SSO approvals
(`/api/v1/tenants/{t}/settings/sso/changes/{id}/approve|reject`, owner only,
re-checked in the database); approval writes the live config and marks the
change approved in one transaction. Changes expire after 7 days; a newer
submission supersedes an older one. An organization with no active owner yet
(first-time setup) gets the change applied directly. Deleting a SAML config or
an identity provider, SSO enforcement and verified domains apply directly.
Code: `internal/app/auth/sso_change.go`, `internal/infra/postgres/sso_change_repository.go`,
`internal/infra/http/handler/sso_change_handler.go`.

## Configuration resolution (tenant → env fallback)

`SSOService.resolveProvider(tenantID, provider)` returns the **effective**
config for a login:

1. **Tenant's own provider wins.** If the tenant has an *active* identity
   provider for that type, its config is used (client secret decrypted from the
   DB).
2. **Platform env fallback.** If the tenant has none, and the provider is
   `entra_id` and the platform env fallback is configured, that shared config is
   used instead.
3. Otherwise → `ErrSSOProviderNotFound`.

The login provider list (`GetProvidersForTenant`) mirrors this: when a tenant
has no `entra_id` provider but the env fallback is configured, a synthetic
`entra_id` entry (id `env:entra_id`) is appended so the button still appears. A
tenant's own `entra_id` provider suppresses the fallback entry.

### Env fallback variables (`config.AuthConfig.EntraSSO`)

| Env var | Default | Meaning |
|---------|---------|---------|
| `SSO_ENTRA_ENABLED` | `false` | Master switch for the fallback. |
| `SSO_ENTRA_CLIENT_ID` | — | App (client) ID of the shared Entra app registration. |
| `SSO_ENTRA_CLIENT_SECRET` | — | Client secret (plaintext; env is the trust boundary — no DB encryption). |
| `SSO_ENTRA_TENANT_ID` | `common` | Entra **directory** id. `common` = multi-tenant Microsoft sign-in. |
| `SSO_ENTRA_ALLOWED_DOMAINS` | _(empty = any)_ | CSV email-domain allow-list — important when `TENANT_ID=common`. |
| `SSO_ENTRA_DEFAULT_ROLE` | `viewer` | Role granted to auto-provisioned users (least privilege). |
| `SSO_ENTRA_AUTO_PROVISION` | `true` | Create tenant membership on first login. |
| `SSO_ENTRA_DISPLAY_NAME` | `Microsoft Entra ID` | Button label. |

`EntraSSOConfig.IsConfigured()` requires `Enabled` + a client id + a client
secret.

> The fallback only supplies **credentials and endpoints**. The login is still
> initiated for a specific org (slug); the user is provisioned into *that*
> tenant. With `SSO_ENTRA_TENANT_ID=common`, set `SSO_ENTRA_ALLOWED_DOMAINS` to
> avoid letting arbitrary Microsoft accounts in.

## Layering

| Layer | File |
|-------|------|
| Service | `internal/app/auth/sso.go` (`resolveProvider`, `envProvider`) |
| Config | `internal/config/config.go` (`EntraSSOConfig`) |
| Domain | `pkg/domain/identityprovider/entity.go` (providers, `AuthEndpoints`) |
| Handler/routes | `internal/infra/http/handler/sso_handler.go`, `routes/auth.go` |
| OIDC verifier | `internal/app/auth/oidc_verifier.go` (`oidcVerifier`, JWKS cache) |

## ID-token validation (shipped)

Every tenant OIDC provider (Entra ID, Okta, Google Workspace) must return an
`id_token` in the token-exchange response, and the callback verifies it before
completing login (`SSOService.verifyIDToken` → `oidcVerifier.verify`):

- **Signature** — RS256 only, verified against the provider's JWKS
  (`Provider.JWKSURL`), with keys cached per JWKS URL (1h TTL, refresh on
  unknown `kid`). `alg=none` and non-RS256 are rejected.
- **Audience** — must contain our `client_id`.
- **Expiry** — `exp` required; `exp`/`nbf`/`iat` enforced with 2-minute leeway.
- **Nonce** — must equal the nonce embedded in the signed `state` at authorize
  time (constant-time compare); binds the token to this flow.
- **Issuer** — provider-specific. For Entra the issuer must be
  `https://login.microsoftonline.com/{tid}/v2.0` consistent with the token's
  `tid` claim; single-tenant configs additionally require `tid` to match the
  configured directory, while `common`/`organizations`/`consumers` accept any
  directory (the email domain allow-list still applies). For Okta the issuer
  must be the configured org's default authorization server
  (`{org}/oauth2/default`); for Google it must be `https://accounts.google.com`
  (or `accounts.google.com`).

The check is **fail-closed**, and so is its absence: a token response without
an `id_token`, or a provider with no signing keys (an Okta provider without its
org URL), refuses the login with `ErrSSOInvalidIDToken`. The account's federated
identity (issuer, subject) and the back-channel-logout session binding come only
from the verified `id_token`.

The `openid` scope is therefore required:

- creating or updating a provider with a non-empty scope list that lacks
  `openid` is rejected with `scopes must include "openid"`; an empty list means
  the defaults, which include it;
- a provider saved before this rule (scopes without `openid`) keeps working:
  the authorize request adds `openid` in front of its saved scopes.

For Okta and Google the email still comes from the userinfo endpoint (with its
`email_verified` claim); for Entra it comes from the verified `id_token`.

## Global "Sign in with Microsoft" — nOAuth hardening (shipped)

The global OAuth path (`oauth.go`) uses the multi-tenant `/common` authority, so
**any** Entra tenant can complete the flow. Identity therefore comes from the
**verified `id_token`**, never the mutable Microsoft Graph `mail` attribute — a
rogue tenant can set a user's `mail` to a victim's address without owning the
domain (the "nOAuth" account-takeover class).

`getMicrosoftUserInfo` now:

- verifies the `id_token` (signature via Entra JWKS, audience == `client_id`,
  issuer `https://login.microsoftonline.com/{tid}/v2.0`; nonce is skipped only
  here because the code-flow `id_token` is delivered server-to-server), and
- **requires `xms_edov == true`** ("email domain owner verified") before trusting
  the `email` claim — parity with the verified-email requirement already enforced
  for Google and GitHub. A domain can be verified in exactly one Entra tenant, so
  a domain-verified email is a reliable identifier. Absent/false ⇒ login refused.

The account is also pinned to the immutable `(issuer, subject)`
(`BindFederatedIdentity`); a different federated identity presenting the same
email is rejected.

> **Operator action required:** add the **`xms_edov`** optional claim (ID token)
> to the app registration used for `OAUTH_MICROSOFT_*` (Azure portal → App
> registration → Token configuration → Add optional claim → ID → `xms_edov`).
> Without it, Microsoft logins are refused fail-closed rather than trusting an
> unverified email.
>
> **Expected refusals (by design, not a bug):** because trust requires a
> domain-owner-verified email, the global button refuses **personal Microsoft
> accounts** (outlook.com / live.com / hotmail.com) and **B2B guest users whose
> email is on a domain not verified in the signing tenant**. Work/school accounts
> whose domain the tenant owns get `xms_edov == true` and sign in normally. Use
> the **per-tenant Entra SSO** path to admit specific external identities under an
> explicit domain allow-list.

## Enforce SSO per-tenant (with owner break-glass)

A tenant that has configured SSO can **require** its members to authenticate via
SSO instead of a local password — without ever locking its administrators out.

### Setting

`Settings.Security.SSOEnforced` (bool), toggled via
`PATCH /api/v1/tenants/{tenant}/settings/security` (`{"sso_enforced": true}`),
same admin/owner gate as the other tenant-settings toggles.

**Can't-enable guard:** enabling `sso_enforced` is refused (400, `ErrValidation`)
unless the tenant has a *usable* SSO path — an active per-tenant identity
provider or the opted-in env fallback (`SSOService.HasUsableSSOPath`, which reuses
the exact `GetProvidersForTenant` resolution the login page uses). This stops an
admin enforcing SSO with no way for anyone to sign in. If the checker is not
wired the guard is skipped (logged) — the owner break-glass below is the real
lock-out guarantee.

### How a session's login method is recorded

Each session row carries `sessions.auth_method` (migration `000192`), one of
`password | sso | saml`, and `sessions.idp_tenant_id` (migration `000269`), the
organization whose own identity provider issued it:

| Login path | `auth_method` | `idp_tenant_id` |
|------------|---------------|-----------------|
| local password (with or without 2FA) | `password` | NULL |
| organization OIDC callback (`SSOService.HandleCallback`), incl. the opted-in env fallback | `sso` | that organization |
| organization SAML ACS (`SSOService.CompleteFederatedLogin`) | `saml` | that organization |
| social OAuth — GitHub / Google / personal Microsoft (`OAuthService.createSession`) | `sso` | NULL |
| any session created before migration `000269` | as recorded | NULL |

Both are stamped *before* the row is persisted. Empty / unknown `auth_method`
values default to `password` — fail-closed.

**Why the issuing organization matters.** Users and sessions are global: one
sign-in can be exchanged (`POST /api/v1/auth/token {"tenant_id": …}`) for an
access token in every organization the account belongs to. If "federated" alone
were the exemption, a sign-in through organization B's SAML/OIDC provider — or a
GitHub login — would get into organization A while skipping A's SSO enforcement
and 2FA requirement, even though A never trusted that IdP.

So the exemption is per organization: **`Session.FederatedFor(tenantID)`** is
true only when the session is federated **and** `idp_tenant_id` is that tenant.
For every other organization the session is handled exactly like a password
session (`Session.AuthMethodFor(tenantID)` returns `password`). Social OAuth and
pre-`000269` sessions have no issuing organization, so they are exempt
**nowhere**. `AuthMethod.IsFederated()` alone must not drive a policy exemption.

The env fallback (`SSO_ENTRA_*`) counts as the organization's IdP: it is used
only for an organization the operator opted in (`SSO_ENTRA_ALLOWED_TENANTS`)
and only when that organization has no provider of its own, and the login runs
the organization's own membership and domain checks.

### Enforcement point (tenant-selection / token-mint gate)

Enforcement lives in **`AuthService.enforceSSOPolicy`**, called from
`ExchangeToken` and `RefreshToken` (`internal/app/auth/service.go`) right after
membership is resolved and **before** a tenant-scoped access token is minted.
This is the single choke point a password session must pass to gain access to a
tenant (the JWT carries no tenant; `Login` only returns a global refresh token +
the list of memberships). The decision is the pure `ssoEnforcementDenied`:

The decision is made on the session's method **as seen by this tenant**
(`AuthMethodFor`):

| Session | Role | Tenant enforces SSO | Result |
|---------|------|---------------------|--------|
| password | member/admin/viewer | yes | **denied** — `ErrSSORequired` (403) |
| issued by **this** tenant's IdP (sso / saml) | any | yes | allowed (the tenant's own SSO login is never blocked) |
| issued by **another** organization's IdP | member/admin/viewer | yes | **denied** — sign in through this tenant's IdP |
| social OAuth, or recorded before `000269` | member/admin/viewer | yes | **denied** |
| any | **owner** | yes | allowed — **break-glass** |
| any | any | no | allowed (unaffected) |

The access token's `auth_method` claim is minted the same way
(`AuthMethodFor(tenant)` in `ExchangeToken`, `RefreshToken`, `CreateFirstTeam`
and invitation accept), so the per-request `SSOEnforcementGate` middleware makes
the same decision: a token minted for organization A from organization B's SSO
session carries `auth_method: "password"` and is refused if A enforces SSO, even
if A turned enforcement on after the token was minted.

Re-checked on every `RefreshToken`, so toggling enforcement on takes effect the
next time a password session refreshes (an already-minted access token stays
valid until it expires — a bounded window; see follow-ups).

### Break-glass guarantee

The tenant **OWNER is always exempt** and can password-login into an
SSO-enforced tenant. Enabling SSO enforcement therefore can *never* lock every
administrator out — the owner can always get in and turn it back off. The SSO
login path itself is never gated (a session from the tenant's own IdP always
passes), so an enforced tenant always admits the very login method it requires.

### Behavior change (migration `000269`)

Sessions created before the issuing organization was recorded have none, and are
treated as not exempt anywhere (fail closed). After the upgrade, a non-owner
member of an SSO-enforced organization whose current session came from SSO is
refused at the next token refresh (`403`, "requires SSO sign-in") and simply
signs in again through the organization's IdP. Likewise, a federated session
used for an organization that requires 2FA (`mfa_required`) gets
`MFA_ENROLLMENT_REQUIRED` unless that organization's IdP issued it; see
[user-two-factor-authentication.md](user-two-factor-authentication.md).

## Known follow-ups (not yet shipped)

- **SAML / SCIM** — not supported (only OIDC/OAuth). See `docs/IDEAS.md` §3.5.
- The env fallback currently covers `entra_id` only; Okta/Google could follow
  the same `envProvider` seam.
- **SSO-enforcement residual window** — closed: the access token carries the
  `auth_method` claim (per tenant, see above) and `SSOEnforcementGate`
  re-checks it on every request (cached for 60 s).
- **Invitation accept does not run the mint-time policy gates.**
  `AcceptInvitationWithRefreshToken` mints a token for the joined organization
  without `enforceSSOPolicy` / `enforceMFAPolicy`. The per-request SSO gate still
  refuses a non-SSO token for an SSO-enforced organization; the 2FA requirement
  applies from the next refresh (within one access-token lifetime).
- **`HasUsableSSOPath` covers OIDC/env only**, not SAML-only tenants; a
  SAML-only tenant can't yet pass the *can't-enable* guard (the owner break-glass
  still prevents any lock-out).
