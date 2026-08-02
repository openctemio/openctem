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

Security: outbound calls use `httpsec.SafeHTTPClient` (refuses loopback/RFC1918/
link-local), Entra/Graph hosts are fixed strings, an email is required, and the
email domain is checked against the provider's allow-list.

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
| `SSO_ENTRA_DEFAULT_ROLE` | `member` | Role granted to auto-provisioned users. |
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

When the provider returns an `id_token` in the token-exchange response, the
callback verifies it before completing login (`SSOService.verifyIDToken` →
`oidcVerifier.verify`):

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
  directory (the email domain allow-list still applies).

The check is **fail-closed** when an `id_token` is present. It is skipped when
the provider returns no `id_token` (e.g. a tenant IdP configured without the
`openid` scope) — the token response is server-to-server over TLS, so a missing
`id_token` is not attacker-controllable. The access-token → Graph `/me` call
remains the identity source; id_token validation is authenticity/replay
hardening on top.

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
`password | sso | saml`:

- the **password** login path keeps the `AuthMethodPassword` default;
- the **OIDC/OAuth** callback stamps `sso`, the **SAML** ACS stamps `saml`
  (`SSOService.createSession`, `OAuthService.createSession`) *before* the row is
  persisted.

`AuthMethod.IsFederated()` (true for `sso`/`saml`) is the discriminator. Empty /
unknown values default to `password` — fail-closed, so a pre-migration row cannot
silently bypass enforcement.

### Enforcement point (tenant-selection / token-mint gate)

Enforcement lives in **`AuthService.enforceSSOPolicy`**, called from
`ExchangeToken` and `RefreshToken` (`internal/app/auth/service.go`) right after
membership is resolved and **before** a tenant-scoped access token is minted.
This is the single choke point a password session must pass to gain access to a
tenant (the JWT carries no tenant; `Login` only returns a global refresh token +
the list of memberships). The decision is the pure `ssoEnforcementDenied`:

| Session method | Role | Tenant enforces SSO | Result |
|----------------|------|---------------------|--------|
| password | member/admin/viewer | yes | **denied** — `ErrSSORequired` (403) |
| password | **owner** | yes | allowed — **break-glass** |
| sso / saml | any | yes | allowed (SSO login is never blocked) |
| any | any | no | allowed (unaffected) |

Re-checked on every `RefreshToken`, so toggling enforcement on takes effect the
next time a password session refreshes (an already-minted access token stays
valid until it expires — a bounded window; see follow-ups).

### Break-glass guarantee

The tenant **OWNER is always exempt** and can password-login into an
SSO-enforced tenant. Enabling SSO enforcement therefore can *never* lock every
administrator out — the owner can always get in and turn it back off. The SSO
login path itself is never gated (a federated session always passes), so an
enforced tenant always admits the very login method it requires.

## Known follow-ups (not yet shipped)

- **SAML / SCIM** — not supported (only OIDC/OAuth). See `docs/IDEAS.md` §3.5.
- The env fallback currently covers `entra_id` only; Okta/Google could follow
  the same `envProvider` seam.
- **SSO-enforcement residual window:** enforcement is applied at token *mint*
  (ExchangeToken/RefreshToken), not per-request. A password session that already
  holds a valid tenant-scoped access token keeps access until it expires. A
  follow-up could add the auth method to the JWT claim and re-check in the
  `RequireMembership` middleware to close that window.
- **`HasUsableSSOPath` covers OIDC/env only**, not SAML-only tenants; a
  SAML-only tenant can't yet pass the *can't-enable* guard (the owner break-glass
  still prevents any lock-out).
