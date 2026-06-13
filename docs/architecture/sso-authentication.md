# SSO Authentication (per-tenant + platform fallback)

> How OpenCTEM authenticates users against external identity providers, and how
> the **Microsoft Entra ID** login resolves its configuration: a tenant's own
> config first, then a platform-wide env fallback.

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

## Known follow-ups (not yet shipped)

- **ID-token validation.** The callback authenticates via the access token →
  Microsoft Graph `/me`; it does not yet verify the `id_token` signature or the
  `nonce` claim. The `nonce` is sent on authorize but unused on callback.
  Hardening opportunity (full OIDC), not a functional blocker for Entra/Graph.
- **SAML / SCIM** — not supported (only OIDC/OAuth). See `docs/IDEAS.md` §3.5.
- The env fallback currently covers `entra_id` only; Okta/Google could follow
  the same `envProvider` seam.
